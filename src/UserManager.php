<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://www.delight.im/)
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

/**
 * Abstract base class for components implementing user management
 *
 * @internal
 */
abstract class UserManager {

	/** @var string session field for whether the client is currently signed in */
	const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';

	/** @var string session field for the ID of the user who is currently signed in (if any) */
	const SESSION_FIELD_USER_ID = 'auth_user_id';

	/** @var string session field for the email address of the user who is currently signed in (if any) */
	const SESSION_FIELD_EMAIL = 'auth_email';

	/** @var string session field for the display name (if any) of the user who is currently signed in (if any) */
	const SESSION_FIELD_USERNAME = 'auth_username';

	/** @var string session field for the status of the user who is currently signed in (if any) */
	const SESSION_FIELD_STATUS = 'auth_status';

	/** @var string session field for the roles of the user who is currently signed in (if any) */
	const SESSION_FIELD_ROLES = 'auth_roles';

	/** @var string session field for whether the user has been remembered */
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';

	/** @var string session field for last synchronization timestamp */
	const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';

	/** @var string session field for forced logout counter */
	const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';

	/** @var string session field for 2FA first-factor expiration */
	const SESSION_FIELD_AWAITING_2FA_UNTIL = 'auth_awaiting_2fa_until';

	/** @var string session field for 2FA user ID */
	const SESSION_FIELD_AWAITING_2FA_USER_ID = 'auth_awaiting_2fa_user_id';

	/** @var string session field for 2FA remember duration */
	const SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION = 'auth_awaiting_2fa_remember_duration';

	/** @var PdoDatabase */
	protected $db;

	/** @var string|null */
	protected $dbSchema;

	/** @var string */
	protected $dbTablePrefix;

	/**
	 * Creates a random string with the given maximum length
	 *
	 * Uses a cryptographically-secure random number generator.
	 *
	 * @param int $maxLength
	 * @return string
	 */
	public static function createRandomString($maxLength = 24) {
		$bytes = \floor((int) $maxLength / 4) * 3;

		/*
		 * CWE-330:
		 * random_bytes uses the operating system's cryptographically-secure
		 * random number generator and fails closed by throwing an exception
		 * if secure randomness cannot be obtained.
		 */
		$data = \random_bytes($bytes);

		try {
			return Base64::encodeUrlSafe($data);
		}
		finally {
			/*
			 * PHP does not guarantee secure zeroization of immutable strings,
			 * but removing references reduces their lifetime in the current scope.
			 */
			unset($data);
		}
	}

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection
	 * @param string|null $dbTablePrefix
	 * @param string|null $dbSchema
	 */
	protected function __construct($databaseConnection, $dbTablePrefix = null, $dbSchema = null) {
		if ($databaseConnection instanceof PdoDatabase) {
			$this->db = $databaseConnection;
		}
		elseif ($databaseConnection instanceof PdoDsn) {
			$this->db = PdoDatabase::fromDsn($databaseConnection);
		}
		elseif ($databaseConnection instanceof \PDO) {
			$this->db = PdoDatabase::fromPdo($databaseConnection, true);
		}
		else {
			$this->db = null;

			throw new \InvalidArgumentException(
				'The database connection must be an instance of either `PdoDatabase`, `PdoDsn` or `PDO`'
			);
		}

		$this->dbSchema = $dbSchema !== null ? (string) $dbSchema : null;
		$this->dbTablePrefix = (string) $dbTablePrefix;
	}

	/**
	 * Creates a new user
	 *
	 * @param bool $requireUniqueUsername
	 * @param string $email
	 * @param string $password
	 * @param string|null $username
	 * @param callable|null $callback
	 * @return int
	 * @throws InvalidEmailException
	 * @throws InvalidPasswordException
	 * @throws UserAlreadyExistsException
	 * @throws DuplicateUsernameException
	 * @throws AuthError
	 */
	protected function createUserInternal(
		$requireUniqueUsername,
		$email,
		$password,
		$username = null,
		callable $callback = null
	) {
		\ignore_user_abort(true);

		$email = self::validateEmailAddress($email);
		$password = self::validatePassword($password, true);

		$username = isset($username) ? \trim($username) : null;

		if ($username === '') {
			$username = null;
		}

		if ($requireUniqueUsername && $username !== null) {
			try {
				$occurrencesOfUsername = $this->db->selectValue(
					'SELECT COUNT(*) FROM ' . $this->makeTableName('users') . ' WHERE username = ?',
					[ $username ]
				);
			}
			catch (Error $e) {
				/*
				 * CWE-209:
				 * Never propagate database driver messages, SQL statements,
				 * schema names, table names or connection information.
				 */
				throw new DatabaseError();
			}

			if ($occurrencesOfUsername > 0) {
				throw new DuplicateUsernameException();
			}
		}

		/*
		 * PasswordHash::from must internally use a strong password-specific
		 * algorithm such as Argon2id or bcrypt.
		 *
		 * The plaintext value is replaced immediately after hashing so the
		 * original secret is no longer referenced by this local variable.
		 */
		$passwordHash = PasswordHash::from($password);
		unset($password);

		$verified = \is_callable($callback) ? 0 : 1;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users'),
				[
					'email' => $email,
					'password' => $passwordHash,
					'username' => $username,
					'verified' => $verified,
					'registered' => \time()
				]
			);
		}
		catch (IntegrityConstraintViolationException $e) {
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			/*
			 * CWE-209:
			 * Deliberately discard the original DB error message.
			 */
			throw new DatabaseError();
		}
		finally {
			unset($passwordHash);
		}

		$newUserId = (int) $this->db->getLastInsertId();

		if ($verified === 0) {
			$this->createConfirmationRequest($newUserId, $email, $callback);
		}

		return $newUserId;
	}

	/**
	 * Updates the given user's password
	 *
	 * @param int $userId
	 * @param string $newPassword
	 * @throws UnknownIdException
	 * @throws AuthError
	 */
	protected function updatePasswordInternal($userId, $newPassword) {
		/*
		 * Validate before hashing, preserving expected password semantics.
		 */
		$newPassword = self::validatePassword($newPassword, true);

		$passwordHash = PasswordHash::from($newPassword);
		unset($newPassword);

		try {
			$affected = $this->db->update(
				$this->makeTableNameComponents('users'),
				[ 'password' => $passwordHash ],
				[ 'id' => $userId ]
			);

			if ($affected === 0) {
				throw new UnknownIdException();
			}
		}
		catch (Error $e) {
			/*
			 * CWE-209:
			 * Do not disclose database implementation details.
			 */
			throw new DatabaseError();
		}
		finally {
			unset($passwordHash);
		}
	}

	/**
	 * Called when a user has successfully logged in
	 *
	 * @param int $userId
	 * @param string $email
	 * @param string $username
	 * @param int $status
	 * @param int $roles
	 * @param int $forceLogout
	 * @param bool $remembered
	 * @throws AuthError
	 */
	protected function onLoginSuccessful(
		$userId,
		$email,
		$username,
		$status,
		$roles,
		$forceLogout,
		$remembered
	) {
		/*
		 * CWE-384:
		 * Regenerate the session identifier after successful authentication.
		 * The old session identifier must not remain reusable.
		 */
		Session::regenerate(true);

		$_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
		$_SESSION[self::SESSION_FIELD_USER_ID] = (int) $userId;
		$_SESSION[self::SESSION_FIELD_EMAIL] = $email;
		$_SESSION[self::SESSION_FIELD_USERNAME] = $username;
		$_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
		$_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
		$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = (int) $forceLogout;
		$_SESSION[self::SESSION_FIELD_REMEMBERED] = (bool) $remembered;
		$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();

		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = null;
		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = null;
		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION] = null;
	}

	/**
	 * Returns requested user data for an account
	 *
	 * @param string $username
	 * @param array $requestedColumns
	 * @return array
	 * @throws UnknownUsernameException
	 * @throws AmbiguousUsernameException
	 * @throws AuthError
	 */
	protected function getUserDataByUsername($username, array $requestedColumns) {
		try {
			$projection = \implode(', ', $requestedColumns);

			$users = $this->db->select(
				'SELECT ' . $projection
					. ' FROM ' . $this->makeTableName('users')
					. ' WHERE username = ? LIMIT 2 OFFSET 0',
				[ $username ]
			);
		}
		catch (Error $e) {
			/*
			 * CWE-209:
			 * Database messages can contain SQL, column names, schemas,
			 * credentials, hostnames and database engine information.
			 */
			throw new DatabaseError();
		}

		if (empty($users)) {
			throw new UnknownUsernameException();
		}

		if (\count($users) === 1) {
			return $users[0];
		}

		throw new AmbiguousUsernameException();
	}

	/**
	 * Validates an email address
	 *
	 * @param string $email
	 * @return string
	 * @throws InvalidEmailException
	 */
	protected static function validateEmailAddress($email) {
		if (empty($email)) {
			throw new InvalidEmailException();
		}

		$email = \trim($email);

		if (!\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
			throw new InvalidEmailException();
		}

		return $email;
	}

	/**
	 * Validates a password
	 *
	 * @param string $password
	 * @param bool|null $isNewPassword
	 * @return string
	 * @throws InvalidPasswordException
	 */
	protected static function validatePassword($password, $isNewPassword = null) {
		if (empty($password)) {
			throw new InvalidPasswordException();
		}

		$password = \trim($password);

		$isNewPassword = ($isNewPassword !== null)
			? (bool) $isNewPassword
			: false;

		if (\strlen($password) < 1) {
			throw new InvalidPasswordException();
		}

		if ($isNewPassword && \strlen($password) > 2048) {
			throw new InvalidPasswordException();
		}

		return $password;
	}

	/**
	 * Creates a request for email confirmation
	 *
	 * @param int $userId
	 * @param string $email
	 * @param callable $callback
	 * @throws AuthError
	 */
	protected function createConfirmationRequest($userId, $email, callable $callback) {
		/*
		 * Both values originate exclusively from a CSPRNG.
		 *
		 * The selector is intentionally persisted in plaintext because it
		 * serves only as a lookup identifier.
		 *
		 * The authentication token itself is never persisted in plaintext.
		 */
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);

		/*
		 * TokenHash::from must use a one-way cryptographic hash suitable
		 * for authentication tokens.
		 */
		$tokenHashed = TokenHash::from($token);

		$expires = \time() + 60 * 60 * 24;

		try {
			$this->db->insert(
				$this->makeTableNameComponents('users_confirmations'),
				[
					'user_id' => (int) $userId,
					'email' => $email,
					'selector' => $selector,
					'token' => $tokenHashed,
					'expires' => $expires
				]
			);
		}
		catch (Error $e) {
			/*
			 * CWE-209:
			 * Do not expose DBMS-generated error text.
			 */
			throw new DatabaseError();
		}

		try {
			if (\is_callable($callback)) {
				/*
				 * The plaintext token exists only because it must be delivered
				 * to the user. It must never be logged or persisted.
				 */
				$callback($selector, $token);
			}
			else {
				throw new MissingCallbackError();
			}
		}
		finally {
			/*
			 * Reduce lifetime of authentication secrets in the scope.
			 *
			 * Note: PHP does not provide guaranteed secure memory zeroization
			 * for normal string variables, therefore this is reference/lifetime
			 * minimization rather than guaranteed memory erasure.
			 */
			unset($token, $tokenHashed, $selector);
		}
	}

	/**
	 * Clears an existing "remember me" directive
	 *
	 * @param int $userId
	 * @param string $selector
	 * @throws AuthError
	 */
	protected function deleteRememberDirectiveForUserById($userId, $selector = null) {
		$whereMappings = [];

		if (isset($selector)) {
			$whereMappings['selector'] = (string) $selector;
		}

		$whereMappings['user'] = (int) $userId;

		try {
			$this->db->delete(
				$this->makeTableNameComponents('users_remembered'),
				$whereMappings
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Triggers a forced logout for all user sessions
	 *
	 * @param int $userId
	 * @throws AuthError
	 */
	protected function forceLogoutForUserById($userId) {
		$this->deleteRememberDirectiveForUserById($userId);

		try {
			$this->db->exec(
				'UPDATE ' . $this->makeTableName('users')
					. ' SET force_logout = force_logout + 1 WHERE id = ?',
				[ $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError();
		}
	}

	/**
	 * Builds table name components
	 *
	 * @param string $name
	 * @return string[]
	 */
	protected function makeTableNameComponents($name) {
		$components = [];

		if (!empty($this->dbSchema)) {
			$components[] = $this->dbSchema;
		}

		if (!empty($name)) {
			if (!empty($this->dbTablePrefix)) {
				$components[] = $this->dbTablePrefix . $name;
			}
			else {
				$components[] = $name;
			}
		}

		return $components;
	}

	/**
	 * Builds full qualified table name
	 *
	 * @param string $name
	 * @return string
	 */
	protected function makeTableName($name) {
		$components = $this->makeTableNameComponents($name);

		return \implode('.', $components);
	}

}
```

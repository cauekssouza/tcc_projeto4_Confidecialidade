<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im (https://delight.im/)
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

	/** @var string session field for the display name (if any) */
	const SESSION_FIELD_USERNAME = 'auth_username';

	/** @var string session field for the status of the user */
	const SESSION_FIELD_STATUS = 'auth_status';

	/** @var string session field for the roles of the user */
	const SESSION_FIELD_ROLES = 'auth_roles';

	/** @var string session field for whether the user has been remembered */
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';

	/** @var string timestamp of the session data's last resynchronization */
	const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';

	/** @var string counter that keeps track of forced logouts */
	const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';

	/** @var string timestamp until which first-factor authentication is valid */
	const SESSION_FIELD_AWAITING_2FA_UNTIL = 'auth_awaiting_2fa_until';

	/** @var string ID of the user awaiting the second factor */
	const SESSION_FIELD_AWAITING_2FA_USER_ID = 'auth_awaiting_2fa_user_id';

	/** @var string desired "remember me" duration during 2FA */
	const SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION = 'auth_awaiting_2fa_remember_duration';


	/** @var PdoDatabase the database connection to operate on */
	protected $db;

	/** @var string|null schema name for all database tables */
	protected $dbSchema;

	/** @var string prefix for the names of all database tables */
	protected $dbTablePrefix;


	/**
	 * Best-effort removal of sensitive strings from the current scope.
	 *
	 * sodium_memzero is used where available because simply calling unset
	 * or overwriting a PHP variable cannot guarantee that the original
	 * string buffer has been erased immediately.
	 *
	 * @param mixed $value
	 * @return void
	 */
	private static function clearSensitiveValue(&$value) {
		if (\is_string($value) && \function_exists('sodium_memzero')) {
			\sodium_memzero($value);
		}
		else {
			$value = null;
		}
	}

	/**
	 * Creates a random string with the given maximum length.
	 *
	 * @param int $maxLength maximum length of the output string
	 * @return string new random string
	 */
	public static function createRandomString($maxLength = 24) {
		$bytes = \floor((int) $maxLength / 4) * 3;

		if ($bytes <= 0) {
			return '';
		}

		/*
		 * CWE-330:
		 *
		 * Prefer PHP's operating-system-backed CSPRNG.
		 * Keep OpenSSL as a compatibility fallback for older PHP versions.
		 */
		if (\function_exists('random_bytes')) {
			$data = \random_bytes($bytes);
		}
		else {
			$cryptoStrong = false;

			$data = \openssl_random_pseudo_bytes(
				$bytes,
				$cryptoStrong
			);

			/*
			 * Never silently continue with insufficient randomness.
			 */
			if ($data === false || $cryptoStrong !== true) {
				throw new \RuntimeException(
					'Cryptographically secure random data could not be generated'
				);
			}
		}

		try {
			return Base64::encodeUrlSafe($data);
		}
		finally {
			/*
			 * Random source material is no longer needed after
			 * creation of its URL-safe representation.
			 */
			self::clearSensitiveValue($data);
		}
	}

	/**
	 * @param PdoDatabase|PdoDsn|\PDO $databaseConnection
	 * @param string|null $dbTablePrefix
	 * @param string|null $dbSchema
	 */
	protected function __construct(
		$databaseConnection,
		$dbTablePrefix = null,
		$dbSchema = null
	) {
		if ($databaseConnection instanceof PdoDatabase) {
			$this->db = $databaseConnection;
		}
		elseif ($databaseConnection instanceof PdoDsn) {
			$this->db = PdoDatabase::fromDsn($databaseConnection);
		}
		elseif ($databaseConnection instanceof \PDO) {
			$this->db = PdoDatabase::fromPdo(
				$databaseConnection,
				true
			);
		}
		else {
			$this->db = null;

			throw new \InvalidArgumentException(
				'The database connection must be an instance of either `PdoDatabase`, `PdoDsn` or `PDO`'
			);
		}

		$this->dbSchema = $dbSchema !== null
			? (string) $dbSchema
			: null;

		$this->dbTablePrefix = (string) $dbTablePrefix;
	}

	/**
	 * Creates a new user.
	 *
	 * @param bool $requireUniqueUsername
	 * @param string $email
	 * @param string $password
	 * @param string|null $username
	 * @param callable|null $callback
	 * @return int
	 *
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

		/*
		 * PasswordHash::from is intentionally retained.
		 *
		 * PHP-Auth uses this abstraction for its password hashing and
		 * verification strategy, allowing bcrypt/stronger algorithms and
		 * transparent hash upgrades without breaking compatibility with
		 * the rest of the library.
		 *
		 * The plaintext password is discarded immediately after hashing.
		 */
		$passwordHash = null;

		try {
			$passwordHash = PasswordHash::from($password);
		}
		finally {
			self::clearSensitiveValue($password);
		}

		$username = isset($username)
			? \trim($username)
			: null;

		if ($username === '') {
			$username = null;
		}

		if ($requireUniqueUsername && $username !== null) {
			try {
				$occurrencesOfUsername = $this->db->selectValue(
					'SELECT COUNT(*) FROM '
						. $this->makeTableName('users')
						. ' WHERE username = ?',
					[ $username ]
				);
			}
			catch (Error $e) {
				/*
				 * CWE-209:
				 * Never propagate SQL, schema, table, driver or
				 * connection details from the original exception.
				 */
				throw new DatabaseError(
					'An internal database operation failed'
				);
			}

			if ($occurrencesOfUsername > 0) {
				throw new DuplicateUsernameException();
			}
		}

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

			$newUserId = (int) $this->db->getLastInsertId();
		}
		catch (IntegrityConstraintViolationException $e) {
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			/*
			 * Do not expose:
			 * - SQL queries
			 * - table/schema names
			 * - DB host or credentials
			 * - driver messages
			 * - constraint names
			 */
			throw new DatabaseError(
				'An internal database operation failed'
			);
		}
		finally {
			/*
			 * Although a password hash is not plaintext, keeping its
			 * lifetime short reduces unnecessary exposure.
			 */
			self::clearSensitiveValue($passwordHash);
		}

		if ($verified === 0) {
			$this->createConfirmationRequest(
				$newUserId,
				$email,
				$callback
			);
		}

		return $newUserId;
	}

	/**
	 * Updates the given user's password.
	 *
	 * @param int $userId
	 * @param string $newPassword
	 *
	 * @throws UnknownIdException
	 * @throws AuthError
	 */
	protected function updatePasswordInternal(
		$userId,
		$newPassword
	) {
		$passwordHash = null;

		try {
			$passwordHash = PasswordHash::from($newPassword);
		}
		finally {
			/*
			 * Ensure that the local scope no longer references
			 * the plaintext password after hashing.
			 */
			self::clearSensitiveValue($newPassword);
		}

		try {
			$affected = $this->db->update(
				$this->makeTableNameComponents('users'),
				[
					'password' => $passwordHash
				],
				[
					'id' => $userId
				]
			);

			if ($affected === 0) {
				throw new UnknownIdException();
			}
		}
		catch (Error $e) {
			throw new DatabaseError(
				'An internal database operation failed'
			);
		}
		finally {
			self::clearSensitiveValue($passwordHash);
		}
	}

	/**
	 * Called when a user has successfully logged in.
	 *
	 * @param int $userId
	 * @param string $email
	 * @param string $username
	 * @param int $status
	 * @param int $roles
	 * @param int $forceLogout
	 * @param bool $remembered
	 *
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
		 *
		 * Explicitly regenerate the session identifier after successful
		 * authentication, invalidating the previous session ID.
		 */
		Session::regenerate(true);

		$_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
		$_SESSION[self::SESSION_FIELD_USER_ID] = (int) $userId;
		$_SESSION[self::SESSION_FIELD_EMAIL] = $email;
		$_SESSION[self::SESSION_FIELD_USERNAME] = $username;
		$_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
		$_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
		$_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = (int) $forceLogout;
		$_SESSION[self::SESSION_FIELD_REMEMBERED] = $remembered;
		$_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();

		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = null;
		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = null;
		$_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION] = null;
	}

	/**
	 * Returns requested user data for the account with the specified username.
	 *
	 * @param string $username
	 * @param array $requestedColumns
	 * @return array
	 *
	 * @throws UnknownUsernameException
	 * @throws AmbiguousUsernameException
	 * @throws AuthError
	 */
	protected function getUserDataByUsername(
		$username,
		array $requestedColumns
	) {
		try {
			/*
			 * IMPORTANT:
			 * requestedColumns must continue to originate exclusively
			 * from trusted application/library code.
			 */
			$projection = \implode(', ', $requestedColumns);

			$users = $this->db->select(
				'SELECT '
					. $projection
					. ' FROM '
					. $this->makeTableName('users')
					. ' WHERE username = ? LIMIT 2 OFFSET 0',
				[ $username ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError(
				'An internal database operation failed'
			);
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
	 * Validates an email address.
	 *
	 * @param string $email
	 * @return string
	 *
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
	 * Validates a password.
	 *
	 * @param string $password
	 * @param bool|null $isNewPassword
	 * @return string
	 *
	 * @throws InvalidPasswordException
	 */
	protected static function validatePassword(
		$password,
		$isNewPassword = null
	) {
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

		if ($isNewPassword) {
			if (\strlen($password) > 2048) {
				throw new InvalidPasswordException();
			}
		}

		return $password;
	}

	/**
	 * Creates a request for email confirmation.
	 *
	 * @param int $userId
	 * @param string $email
	 * @param callable $callback
	 *
	 * @throws AuthError
	 */
	protected function createConfirmationRequest(
		$userId,
		$email,
		callable $callback
	) {
		$selector = self::createRandomString(16);
		$token = self::createRandomString(16);
		$tokenHashed = null;

		try {
			/*
			 * Retain TokenHash::from so token verification remains
			 * compatible with PHP-Auth's confirmation flow.
			 *
			 * Only the hash is persisted. The plaintext token exists
			 * only for the duration required to send it to the user.
			 */
			$tokenHashed = TokenHash::from($token);

			$expires = \time() + 60 * 60 * 24;

			try {
				$this->db->insert(
					$this->makeTableNameComponents(
						'users_confirmations'
					),
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
				throw new DatabaseError(
					'An internal database operation failed'
				);
			}

			if (\is_callable($callback)) {
				/*
				 * The plaintext token must be available here because
				 * it is the credential that needs to reach the user.
				 */
				$callback($selector, $token);
			}
			else {
				throw new MissingCallbackError();
			}
		}
		finally {
			/*
			 * Minimize lifetime of confirmation credentials after the
			 * callback has consumed them.
			 *
			 * Copies explicitly retained by the callback cannot be
			 * erased from this scope.
			 */
			self::clearSensitiveValue($token);
			self::clearSensitiveValue($tokenHashed);
			self::clearSensitiveValue($selector);
		}
	}

	/**
	 * Clears an existing "remember me" directive.
	 *
	 * @param int $userId
	 * @param string $selector
	 *
	 * @throws AuthError
	 */
	protected function deleteRememberDirectiveForUserById(
		$userId,
		$selector = null
	) {
		$whereMappings = [];

		if (isset($selector)) {
			$whereMappings['selector'] = (string) $selector;
		}

		$whereMappings['user'] = (int) $userId;

		try {
			$this->db->delete(
				$this->makeTableNameComponents(
					'users_remembered'
				),
				$whereMappings
			);
		}
		catch (Error $e) {
			throw new DatabaseError(
				'An internal database operation failed'
			);
		}
	}

	/**
	 * Triggers a forced logout in all sessions of the specified user.
	 *
	 * @param int $userId
	 *
	 * @throws AuthError
	 */
	protected function forceLogoutForUserById($userId) {
		$this->deleteRememberDirectiveForUserById($userId);

		try {
			$this->db->exec(
				'UPDATE '
					. $this->makeTableName('users')
					. ' SET force_logout = force_logout + 1 WHERE id = ?',
				[ $userId ]
			);
		}
		catch (Error $e) {
			throw new DatabaseError(
				'An internal database operation failed'
			);
		}
	}

	/**
	 * Builds a qualified full table name.
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
	 * Builds a qualified full table name.
	 *
	 * @param string $name
	 * @return string
	 */
	protected function makeTableName($name) {
		$components = $this->makeTableNameComponents($name);

		return \implode('.', $components);
	}

}

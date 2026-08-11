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

	/** @var string session field for the status of the user */
	const SESSION_FIELD_STATUS = 'auth_status';

	/** @var string session field for the roles of the user */
	const SESSION_FIELD_ROLES = 'auth_roles';

	/** @var string session field for whether the user has been remembered */
	const SESSION_FIELD_REMEMBERED = 'auth_remembered';

	/** @var string session field for the last database resynchronization */
	const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';

	/** @var string session field for the forced logout counter */
	const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';

	/** @var string session field for expiration of the first authentication factor */
	const SESSION_FIELD_AWAITING_2FA_UNTIL = 'auth_awaiting_2fa_until';

	/** @var string session field for the user awaiting 2FA */
	const SESSION_FIELD_AWAITING_2FA_USER_ID = 'auth_awaiting_2fa_user_id';

	/** @var string session field for desired "remember me" duration */
	const SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION = 'auth_awaiting_2fa_remember_duration';

	/**
	 * Generic database error message.
	 *
	 * Never include database driver messages, SQL statements, table names,
	 * schema names, credentials or other implementation details here.
	 */
	const DATABASE_ERROR_MESSAGE = 'An internal database error occurred';

	/** @var PdoDatabase the database connection to operate on */
	protected $db;

	/** @var string|null schema name */
	protected $dbSchema;

	/** @var string table prefix */
	protected $dbTablePrefix;

	/**
	 * Best-effort removal of a sensitive string from the current scope.
	 *
	 * sodium_memzero is used when available to overwrite the string's
	 * memory before the variable is released.
	 *
	 * PHP does not provide an absolute guarantee that all previous copies
	 * created internally by the runtime have been overwritten. This method
	 * nevertheless minimizes the lifetime of plaintext secrets in this scope.
	 *
	 * @param string|null $value
	 * @return void
	 */
	private static function clearSensitiveString(&$value) {
		if (\is_string($value)) {
			if (
				$value !== ''
				&& \function_exists('sodium_memzero')
			) {
				\sodium_memzero($value);
			}

			$value = null;
		}

		unset($value);
	}

	/**
	 * Creates a random string with the given maximum length.
	 *
	 * Uses PHP's CSPRNG through random_bytes.
	 *
	 * @param int $maxLength the maximum length of the output string
	 * @return string the new random string
	 */
	public static function createRandomString($maxLength = 24) {
		$bytes = \floor((int) $maxLength / 4) * 3;

		/*
		 * Preserve valid behavior for the documented input while avoiding
		 * passing zero to random_bytes.
		 */
		if ($bytes <= 0) {
			return Base64::encodeUrlSafe('');
		}

		$data = null;

		try {
			/*
			 * random_bytes is explicitly intended for cryptographic secrets
			 * and relies on the operating system's secure random source.
			 */
			$data = \random_bytes($bytes);

			return Base64::encodeUrlSafe($data);
		}
		finally {
			/*
			 * Raw entropy should not remain unnecessarily available in the
			 * local variable after its Base64 representation has been built.
			 */
			self::clearSensitiveString($data);
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
	 * Creates a new user.
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

		if ($requireUniqueUsername) {
			if ($username !== null) {
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
					 * Never propagate the driver's original diagnostic.
					 */
					throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
				}

				if ($occurrencesOfUsername > 0) {
					throw new DuplicateUsernameException();
				}
			}
		}

		$passwordHash = null;

		try {
			/*
			 * PasswordHash::from uses PHP's password hashing API and keeps
			 * compatibility with PasswordHash::verify used by PHP-Auth.
			 */
			$passwordHash = PasswordHash::from($password);
		}
		finally {
			/*
			 * The plaintext password is no longer required after hashing.
			 */
			self::clearSensitiveString($password);
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
		}
		catch (IntegrityConstraintViolationException $e) {
			/*
			 * Preserve the original public exception contract without
			 * exposing the underlying integrity constraint.
			 */
			throw new UserAlreadyExistsException();
		}
		catch (Error $e) {
			/*
			 * Do NOT use:
			 *
			 *     $e->getMessage()
			 *
			 * Database messages may contain schemas, table names,
			 * column names, SQL fragments or connection information.
			 */
			throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
		}
		finally {
			/*
			 * The password hash is not plaintext, but minimizing its
			 * lifetime in local scope provides additional defense in depth.
			 */
			self::clearSensitiveString($passwordHash);
		}

		$newUserId = (int) $this->db->getLastInsertId();

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
	 * @throws UnknownIdException
	 * @throws AuthError
	 */
	protected function updatePasswordInternal($userId, $newPassword) {
		$passwordHash = null;

		try {
			/*
			 * Use the library's password hashing abstraction instead of
			 * storing or transmitting the plaintext password.
			 */
			$passwordHash = PasswordHash::from($newPassword);
		}
		finally {
			/*
			 * Plaintext password is no longer needed.
			 */
			self::clearSensitiveString($newPassword);
		}

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
			throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
		}
		finally {
			self::clearSensitiveString($passwordHash);
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
		 * CWE-384 — Session Fixation
		 *
		 * A new session identifier is issued after successful
		 * authentication, invalidating the previously supplied identifier.
		 *
		 * `true` preserves the original behavior of this class.
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
	 * Returns requested user data for the account with the username.
	 *
	 * @param string $username
	 * @param array $requestedColumns
	 * @return array
	 * @throws UnknownUsernameException
	 * @throws AmbiguousUsernameException
	 * @throws AuthError
	 */
	protected function getUserDataByUsername(
		$username,
		array $requestedColumns
	) {
		try {
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
			/*
			 * CWE-209:
			 * Do not disclose raw SQL/database diagnostic information.
			 */
			throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
		}

		if (empty($users)) {
			throw new UnknownUsernameException();
		}
		else {
			if (\count($users) === 1) {
				return $users[0];
			}
			else {
				throw new AmbiguousUsernameException();
			}
		}
	}

	/**
	 * Validates an email address.
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
	 * Validates a password.
	 *
	 * @param string $password
	 * @param bool|null $isNewPassword
	 * @return string
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
	 * @throws AuthError
	 */
	protected function createConfirmationRequest(
		$userId,
		$email,
		callable $callback
	) {
		$selector = self::createRandomString(16);

		/*
		 * Plaintext token exists only because the API contract requires it
		 * to be supplied to the callback.
		 */
		$token = self::createRandomString(16);

		$tokenHashed = null;

		try {
			/*
			 * Store only the computationally expensive one-way hash.
			 *
			 * TokenHash::from internally uses PHP's password_hash and is
			 * paired with TokenHash::verify elsewhere in PHP-Auth.
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
				/*
				 * Never expose DBMS diagnostics, SQL or schema details.
				 */
				throw new DatabaseError(
					self::DATABASE_ERROR_MESSAGE
				);
			}

			if (\is_callable($callback)) {
				/*
				 * This is the sole point at which plaintext token exposure
				 * is necessary due to the original public contract.
				 */
				$callback($selector, $token);
			}
			else {
				throw new MissingCallbackError();
			}
		}
		finally {
			/*
			 * Remove secret material as soon as the callback finishes,
			 * including when the callback throws an exception.
			 */
			self::clearSensitiveString($token);
			self::clearSensitiveString($tokenHashed);
		}
	}

	/**
	 * Clears an existing "remember me" directive.
	 *
	 * @param int $userId
	 * @param string $selector
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
				$this->makeTableNameComponents('users_remembered'),
				$whereMappings
			);
		}
		catch (Error $e) {
			throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
		}
	}

	/**
	 * Triggers a forced logout in all sessions belonging to the user.
	 *
	 * @param int $userId
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
			throw new DatabaseError(self::DATABASE_ERROR_MESSAGE);
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

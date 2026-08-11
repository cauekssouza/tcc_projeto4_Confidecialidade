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
 * Base abstrata para componentes responsáveis pelo gerenciamento de usuários.
 *
 * @internal
 */
abstract class UserManager
{
    private const MAX_PASSWORD_LENGTH = 2048;
    private const EMAIL_CONFIRMATION_TTL = 86400; // 24 horas

    /** Campos de sessão */
    const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
    const SESSION_FIELD_USER_ID = 'auth_user_id';
    const SESSION_FIELD_EMAIL = 'auth_email';
    const SESSION_FIELD_USERNAME = 'auth_username';
    const SESSION_FIELD_STATUS = 'auth_status';
    const SESSION_FIELD_ROLES = 'auth_roles';
    const SESSION_FIELD_REMEMBERED = 'auth_remembered';
    const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';
    const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';
    const SESSION_FIELD_AWAITING_2FA_UNTIL = 'auth_awaiting_2fa_until';
    const SESSION_FIELD_AWAITING_2FA_USER_ID = 'auth_awaiting_2fa_user_id';
    const SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION = 'auth_awaiting_2fa_remember_duration';

    /** @var PdoDatabase */
    protected $db;

    /** @var string|null */
    protected $dbSchema;

    /** @var string */
    protected $dbTablePrefix;

    /**
     * Cria uma string criptograficamente segura.
     *
     * O tamanho deve ser múltiplo de 4 para manter a compatibilidade
     * com a representação Base64 URL-safe utilizada pela biblioteca.
     *
     * @param int $maxLength
     * @return string
     */
    public static function createRandomString($maxLength = 24)
    {
        $maxLength = (int) $maxLength;

        if ($maxLength <= 0 || $maxLength % 4 !== 0) {
            throw new \InvalidArgumentException(
                'Random string length must be a positive multiple of 4'
            );
        }

        /*
         * Cada 3 bytes tornam-se aproximadamente 4 caracteres Base64.
         *
         * random_bytes utiliza um CSPRNG fornecido pelo sistema operacional
         * e é preferível a openssl_random_pseudo_bytes para código moderno.
         */
        $numberOfBytes = ($maxLength / 4) * 3;

        return Base64::encodeUrlSafe(
            \random_bytes($numberOfBytes)
        );
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
        $this->db = $this->createDatabaseConnection($databaseConnection);
        $this->dbSchema = $dbSchema !== null ? (string) $dbSchema : null;
        $this->dbTablePrefix = $dbTablePrefix !== null
            ? (string) $dbTablePrefix
            : '';
    }

    /**
     * Normaliza os diferentes tipos de conexão suportados.
     *
     * @param mixed $databaseConnection
     * @return PdoDatabase
     */
    private function createDatabaseConnection($databaseConnection)
    {
        if ($databaseConnection instanceof PdoDatabase) {
            return $databaseConnection;
        }

        if ($databaseConnection instanceof PdoDsn) {
            return PdoDatabase::fromDsn($databaseConnection);
        }

        if ($databaseConnection instanceof \PDO) {
            return PdoDatabase::fromPdo($databaseConnection, true);
        }

        throw new \InvalidArgumentException(
            'The database connection must be an instance of PdoDatabase, PdoDsn or PDO'
        );
    }

    /**
     * Cria um novo usuário.
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
        $username = self::normalizeUsername($username);

        if ($requireUniqueUsername && $username !== null) {
            $this->ensureUsernameIsAvailable($username);
        }

        /*
         * A senha em texto puro só é necessária até este ponto.
         * PasswordHash::from deve utilizar password_hash ou mecanismo
         * equivalente adequado.
         */
        $passwordHash = PasswordHash::from($password);

        // Remove nossa referência à senha em texto puro o quanto antes.
        unset($password);

        $verified = $callback === null ? 1 : 0;

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
             * A constraint UNIQUE do banco deve continuar sendo a
             * proteção definitiva contra condições de corrida.
             */
            throw new UserAlreadyExistsException();
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }

        $userId = (int) $this->db->getLastInsertId();

        if ($verified === 0) {
            $this->createConfirmationRequest(
                $userId,
                $email,
                $callback
            );
        }

        return $userId;
    }

    /**
     * Normaliza o nome de usuário.
     *
     * Ao contrário das senhas, remover espaços das extremidades de
     * usernames é aceitável e desejável.
     *
     * @param string|null $username
     * @return string|null
     */
    private static function normalizeUsername($username)
    {
        if ($username === null) {
            return null;
        }

        $username = \trim((string) $username);

        return $username === '' ? null : $username;
    }

    /**
     * Verifica preventivamente se o username já está em uso.
     *
     * A constraint UNIQUE do banco ainda é necessária para impedir
     * condições de corrida.
     *
     * @param string $username
     */
    private function ensureUsernameIsAvailable($username)
    {
        try {
            $count = (int) $this->db->selectValue(
                'SELECT COUNT(*) FROM '
                . $this->makeTableName('users')
                . ' WHERE username = ?',
                [$username]
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }

        if ($count > 0) {
            throw new DuplicateUsernameException();
        }
    }

    /**
     * Atualiza a senha do usuário.
     *
     * @param int $userId
     * @param string $newPassword
     *
     * @throws InvalidPasswordException
     * @throws UnknownIdException
     * @throws AuthError
     */
    protected function updatePasswordInternal($userId, $newPassword)
    {
        /*
         * O código original aplicava o hash diretamente, sem executar
         * validatePassword. Isso permitia que as regras para novas senhas
         * fossem ignoradas.
         */
        $newPassword = self::validatePassword($newPassword, true);

        $passwordHash = PasswordHash::from($newPassword);

        unset($newPassword);

        try {
            $affectedRows = $this->db->update(
                $this->makeTableNameComponents('users'),
                [
                    'password' => $passwordHash
                ],
                [
                    'id' => (int) $userId
                ]
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }

        if ($affectedRows === 0) {
            throw new UnknownIdException();
        }
    }

    /**
     * Executado depois de uma autenticação bem-sucedida.
     *
     * @param int $userId
     * @param string $email
     * @param string|null $username
     * @param int $status
     * @param int $roles
     * @param int $forceLogout
     * @param bool $remembered
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
         * Fundamental contra Session Fixation.
         */
        Session::regenerate(true);

        $_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
        $_SESSION[self::SESSION_FIELD_USER_ID] = (int) $userId;
        $_SESSION[self::SESSION_FIELD_EMAIL] = (string) $email;
        $_SESSION[self::SESSION_FIELD_USERNAME] = $username;
        $_SESSION[self::SESSION_FIELD_STATUS] = (int) $status;
        $_SESSION[self::SESSION_FIELD_ROLES] = (int) $roles;
        $_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = (int) $forceLogout;
        $_SESSION[self::SESSION_FIELD_REMEMBERED] = (bool) $remembered;
        $_SESSION[self::SESSION_FIELD_LAST_RESYNC] = \time();

        $this->clearPendingTwoFactorAuthentication();
    }

    /**
     * Remove qualquer estado intermediário de 2FA.
     */
    private function clearPendingTwoFactorAuthentication()
    {
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = null;
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = null;
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION] = null;
    }

    /**
     * Retorna dados do usuário identificado pelo username.
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
        $projection = self::buildSafeProjection($requestedColumns);

        try {
            $users = $this->db->select(
                'SELECT '
                . $projection
                . ' FROM '
                . $this->makeTableName('users')
                . ' WHERE username = ? LIMIT 2',
                [
                    $username
                ]
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }

        $numberOfUsers = \count($users);

        if ($numberOfUsers === 0) {
            throw new UnknownUsernameException();
        }

        if ($numberOfUsers > 1) {
            throw new AmbiguousUsernameException();
        }

        return $users[0];
    }

    /**
     * Constrói uma projeção SQL contendo somente identificadores simples.
     *
     * Valores não podem ser usados como parâmetros PDO para nomes de
     * colunas. Assim, qualquer coluna que componha dinamicamente a query
     * deve ser validada explicitamente.
     *
     * @param array $columns
     * @return string
     */
    private static function buildSafeProjection(array $columns)
    {
        if (!$columns) {
            throw new \InvalidArgumentException(
                'At least one column must be requested'
            );
        }

        foreach ($columns as $column) {
            if (
                !\is_string($column)
                || !\preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/D', $column)
            ) {
                throw new \InvalidArgumentException(
                    'Invalid database column requested'
                );
            }
        }

        return \implode(', ', $columns);
    }

    /**
     * Valida um endereço de email.
     *
     * @param string $email
     * @return string
     *
     * @throws InvalidEmailException
     */
    protected static function validateEmailAddress($email)
    {
        if (!\is_string($email)) {
            throw new InvalidEmailException();
        }

        $email = \trim($email);

        if (
            $email === ''
            || \filter_var($email, \FILTER_VALIDATE_EMAIL) === false
        ) {
            throw new InvalidEmailException();
        }

        return $email;
    }

    /**
     * Valida uma senha.
     *
     * IMPORTANTE:
     *
     * Senhas nunca devem ser normalizadas usando trim().
     * Espaços podem fazer parte legitimamente de uma senha e alterar
     * silenciosamente o valor fornecido é um problema de segurança.
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
        if (!\is_string($password) || $password === '') {
            throw new InvalidPasswordException();
        }

        if (
            $isNewPassword === true
            && \strlen($password) > self::MAX_PASSWORD_LENGTH
        ) {
            throw new InvalidPasswordException();
        }

        return $password;
    }

    /**
     * Cria solicitação de confirmação de email.
     *
     * Apenas o hash do token secreto é armazenado no banco.
     * O token puro existe somente para ser entregue ao callback.
     *
     * @param int $userId
     * @param string $email
     * @param callable $callback
     */
    protected function createConfirmationRequest(
        $userId,
        $email,
        callable $callback
    ) {
        /*
         * Selector não precisa ser secreto: ele serve para localizar
         * rapidamente o registro.
         *
         * O token, por outro lado, funciona como credencial e deve possuir
         * alta entropia.
         */
        $selector = self::createRandomString(16);

        /*
         * 32 caracteres Base64 URL-safe fornecem mais entropia que os
         * 16 caracteres usados originalmente.
         *
         * Confirme se seu schema aceita o tamanho utilizado no selector/token
         * conforme necessário.
         */
        $token = self::createRandomString(32);
        $tokenHash = TokenHash::from($token);

        $expiresAt = \time() + self::EMAIL_CONFIRMATION_TTL;

        try {
            $this->db->insert(
                $this->makeTableNameComponents('users_confirmations'),
                [
                    'user_id' => (int) $userId,
                    'email' => $email,
                    'selector' => $selector,
                    'token' => $tokenHash,
                    'expires' => $expiresAt
                ]
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }

        /*
         * Nunca enviar tokenHash ao usuário.
         *
         * O cliente recebe apenas a credencial original. O banco possui
         * somente a versão derivada/hash.
         */
        $callback($selector, $token);

        unset($token);
    }

    /**
     * Remove diretivas "remember me".
     *
     * @param int $userId
     * @param string|null $selector
     */
    protected function deleteRememberDirectiveForUserById(
        $userId,
        $selector = null
    ) {
        $conditions = [
            'user' => (int) $userId
        ];

        if ($selector !== null) {
            $conditions['selector'] = (string) $selector;
        }

        try {
            $this->db->delete(
                $this->makeTableNameComponents('users_remembered'),
                $conditions
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }
    }

    /**
     * Invalida todas as sessões persistentes do usuário.
     *
     * @param int $userId
     */
    protected function forceLogoutForUserById($userId)
    {
        $userId = (int) $userId;

        $this->deleteRememberDirectiveForUserById($userId);

        try {
            $this->db->exec(
                'UPDATE '
                . $this->makeTableName('users')
                . ' SET force_logout = force_logout + 1 WHERE id = ?',
                [
                    $userId
                ]
            );
        }
        catch (Error $e) {
            throw new DatabaseError($e->getMessage());
        }
    }

    /**
     * Constrói os componentes do nome completo da tabela.
     *
     * @param string $name
     * @return string[]
     */
    protected function makeTableNameComponents($name)
    {
        $components = [];

        if ($this->dbSchema !== null && $this->dbSchema !== '') {
            $components[] = $this->dbSchema;
        }

        if ($name === null || $name === '') {
            return $components;
        }

        $components[] = $this->dbTablePrefix . $name;

        return $components;
    }

    /**
     * Constrói o nome completo da tabela.
     *
     * @param string $name
     * @return string
     */
    protected function makeTableName($name)
    {
        return \implode(
            '.',
            $this->makeTableNameComponents($name)
        );
    }
}

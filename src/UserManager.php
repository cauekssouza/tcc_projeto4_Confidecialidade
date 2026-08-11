<?php

/*
 * PHP-Auth (https://github.com/delight-im/PHP-Auth)
 * Copyright (c) delight.im
 * Licensed under the MIT License
 */

namespace Delight\Auth;

use Delight\Base64\Base64;
use Delight\Cookie\Session;
use Delight\Db\PdoDatabase;
use Delight\Db\PdoDsn;
use Delight\Db\Throwable\Error;
use Delight\Db\Throwable\IntegrityConstraintViolationException;

/**
 * Base abstrata para componentes de gerenciamento de usuários.
 *
 * @internal
 */
abstract class UserManager
{
    public const SESSION_FIELD_LOGGED_IN = 'auth_logged_in';
    public const SESSION_FIELD_USER_ID = 'auth_user_id';
    public const SESSION_FIELD_EMAIL = 'auth_email';
    public const SESSION_FIELD_USERNAME = 'auth_username';
    public const SESSION_FIELD_STATUS = 'auth_status';
    public const SESSION_FIELD_ROLES = 'auth_roles';
    public const SESSION_FIELD_REMEMBERED = 'auth_remembered';
    public const SESSION_FIELD_LAST_RESYNC = 'auth_last_resync';
    public const SESSION_FIELD_FORCE_LOGOUT = 'auth_force_logout';
    public const SESSION_FIELD_AWAITING_2FA_UNTIL = 'auth_awaiting_2fa_until';
    public const SESSION_FIELD_AWAITING_2FA_USER_ID = 'auth_awaiting_2fa_user_id';
    public const SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION =
        'auth_awaiting_2fa_remember_duration';

    private const MAX_NEW_PASSWORD_LENGTH = 2048;
    private const CONFIRMATION_TTL_SECONDS = 86400;

    /** @var PdoDatabase */
    protected $db;

    /** @var string|null */
    protected $dbSchema;

    /** @var string */
    protected $dbTablePrefix;

    /**
     * Cria uma string aleatória segura codificada em Base64 URL-safe.
     *
     * O tamanho deve ser múltiplo de 4 porque três bytes resultam
     * em quatro caracteres Base64.
     *
     * @param int $maxLength
     * @return string
     */
    public static function createRandomString($maxLength = 24)
    {
        $maxLength = (int) $maxLength;

        if ($maxLength < 4 || $maxLength % 4 !== 0) {
            throw new \InvalidArgumentException(
                'Random string length must be a positive multiple of 4'
            );
        }

        $bytes = intdiv($maxLength, 4) * 3;

        return Base64::encodeUrlSafe(\random_bytes($bytes));
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
        $this->db = self::createDatabaseConnection($databaseConnection);
        $this->dbSchema = $dbSchema !== null ? (string) $dbSchema : null;
        $this->dbTablePrefix = $dbTablePrefix !== null
            ? (string) $dbTablePrefix
            : '';
    }

    /**
     * @param PdoDatabase|PdoDsn|\PDO $databaseConnection
     * @return PdoDatabase
     */
    private static function createDatabaseConnection($databaseConnection)
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
            'The database connection must be an instance of '
            . '`PdoDatabase`, `PdoDsn` or `PDO`'
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
            $this->assertUsernameAvailable($username);
        }

        /*
         * A senha em texto puro deixa de ser necessária imediatamente
         * depois deste ponto.
         */
        $passwordHash = PasswordHash::from($password);

        /*
         * Não reutilizamos a variável $password para o hash.
         * Isso evita confusão entre segredo em texto puro e hash.
         */
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
                    'registered' => \time(),
                ]
            );
        }
        catch (IntegrityConstraintViolationException $e) {
            /*
             * Não repassamos detalhes da exceção SQL para o chamador.
             */
            throw new UserAlreadyExistsException();
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }

        $userId = (int) $this->db->getLastInsertId();

        if (!$verified) {
            /*
             * Nesse fluxo callback obrigatoriamente existe, pois
             * $verified só é 0 quando callback != null.
             */
            $this->createConfirmationRequest(
                $userId,
                $email,
                $callback
            );
        }

        return $userId;
    }

    /**
     * @param mixed $username
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
     * Verifica rapidamente se já existe um username.
     *
     * SELECT 1 ... LIMIT 1 evita contar todos os registros.
     *
     * @param string $username
     * @return void
     */
    private function assertUsernameAvailable($username)
    {
        try {
            $exists = $this->db->selectValue(
                'SELECT 1'
                . ' FROM ' . $this->makeTableName('users')
                . ' WHERE username = ?'
                . ' LIMIT 1',
                [$username]
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }

        if ($exists !== false && $exists !== null) {
            throw new DuplicateUsernameException();
        }
    }

    /**
     * Atualiza a senha do usuário.
     *
     * @param int $userId
     * @param string $newPassword
     * @return void
     */
    protected function updatePasswordInternal($userId, $newPassword)
    {
        /*
         * O método original fazia o hash sem executar a mesma validação
         * aplicada na criação do usuário.
         */
        $newPassword = self::validatePassword($newPassword, true);
        $passwordHash = PasswordHash::from($newPassword);

        unset($newPassword);

        try {
            $affected = $this->db->update(
                $this->makeTableNameComponents('users'),
                ['password' => $passwordHash],
                ['id' => (int) $userId]
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }

        if ($affected === 0) {
            throw new UnknownIdException();
        }
    }

    /**
     * Chamado após autenticação bem-sucedida.
     *
     * @param int $userId
     * @param string $email
     * @param string|null $username
     * @param int $status
     * @param int $roles
     * @param int $forceLogout
     * @param bool $remembered
     * @return void
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
         * Essencial contra session fixation.
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

        $this->clearPendingTwoFactorSession();
    }

    /**
     * Remove dados temporários relacionados ao primeiro fator do 2FA.
     *
     * @return void
     */
    private function clearPendingTwoFactorSession()
    {
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = null;
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = null;
        $_SESSION[
            self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION
        ] = null;
    }

    /**
     * Busca dados de usuário pelo username.
     *
     * Os parâmetros de valores são enviados separadamente ao banco.
     * Os nomes das colunas, entretanto, fazem parte da própria consulta,
     * portanto precisam ser validados explicitamente.
     *
     * @param string $username
     * @param array $requestedColumns
     * @return array
     */
    protected function getUserDataByUsername(
        $username,
        array $requestedColumns
    ) {
        $projection = self::buildSafeProjection($requestedColumns);

        try {
            $users = $this->db->select(
                'SELECT ' . $projection
                . ' FROM ' . $this->makeTableName('users')
                . ' WHERE username = ?'
                . ' LIMIT 2',
                [$username]
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }

        $count = \count($users);

        if ($count === 0) {
            throw new UnknownUsernameException();
        }

        if ($count > 1) {
            throw new AmbiguousUsernameException();
        }

        return $users[0];
    }

    /**
     * @param array $columns
     * @return string
     */
    private static function buildSafeProjection(array $columns)
    {
        if ($columns === []) {
            throw new \InvalidArgumentException(
                'At least one column must be requested'
            );
        }

        foreach ($columns as $column) {
            if (
                !\is_string($column)
                || !\preg_match(
                    '/\A[a-zA-Z_][a-zA-Z0-9_]*\z/D',
                    $column
                )
            ) {
                throw new \InvalidArgumentException(
                    'Invalid database column name'
                );
            }
        }

        return \implode(', ', $columns);
    }

    /**
     * @param string $email
     * @return string
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
     * Valida uma senha sem modificar o conteúdo informado pelo usuário.
     *
     * IMPORTANTE:
     * não aplicar trim(), strtolower(), normalização arbitrária etc.
     *
     * @param string $password
     * @param bool|null $isNewPassword
     * @return string
     */
    protected static function validatePassword(
        $password,
        $isNewPassword = null
    ) {
        if (!\is_string($password) || $password === '') {
            throw new InvalidPasswordException();
        }

        if (
            (bool) $isNewPassword
            && \strlen($password) > self::MAX_NEW_PASSWORD_LENGTH
        ) {
            throw new InvalidPasswordException();
        }

        return $password;
    }

    /**
     * Cria pedido de confirmação de endereço de e-mail.
     *
     * O token bruto é entregue ao usuário, enquanto apenas seu hash
     * é persistido no banco.
     *
     * @param int $userId
     * @param string $email
     * @param callable $callback
     * @return void
     */
    protected function createConfirmationRequest(
        $userId,
        $email,
        callable $callback
    ) {
        /*
         * Selector pode ser armazenado em claro porque serve para localizar
         * rapidamente o registro. O segredo real é o token.
         *
         * Mantemos 16 caracteres para compatibilidade com esquemas existentes.
         */
        $selector = self::createRandomString(16);

        /*
         * Mais entropia para o segredo. Como apenas o HASH é persistido,
         * aumentar o token normalmente não exige aumentar a coluna token.
         *
         * Caso o protocolo existente exija exatamente 16 caracteres,
         * mantenha o valor anterior.
         */
        $token = self::createRandomString(32);
        $tokenHash = TokenHash::from($token);

        $expires = \time() + self::CONFIRMATION_TTL_SECONDS;

        try {
            $this->db->insert(
                $this->makeTableNameComponents('users_confirmations'),
                [
                    'user_id' => (int) $userId,
                    'email' => (string) $email,
                    'selector' => $selector,
                    'token' => $tokenHash,
                    'expires' => $expires,
                ]
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }

        /*
         * O token em claro só existe durante esta requisição.
         * Nunca deve ser gravado em banco, log ou sistema de analytics.
         */
        $callback($selector, $token);

        unset($token);
    }

    /**
     * @param int $userId
     * @param string|null $selector
     * @return void
     */
    protected function deleteRememberDirectiveForUserById(
        $userId,
        $selector = null
    ) {
        $where = [
            'user' => (int) $userId,
        ];

        if ($selector !== null) {
            $where['selector'] = (string) $selector;
        }

        try {
            $this->db->delete(
                $this->makeTableNameComponents('users_remembered'),
                $where
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }
    }

    /**
     * Força logout de todas as sessões do usuário.
     *
     * @param int $userId
     * @return void
     */
    protected function forceLogoutForUserById($userId)
    {
        $userId = (int) $userId;

        $this->deleteRememberDirectiveForUserById($userId);

        try {
            $this->db->exec(
                'UPDATE ' . $this->makeTableName('users')
                . ' SET force_logout = force_logout + 1'
                . ' WHERE id = ?',
                [$userId]
            );
        }
        catch (Error $e) {
            throw $this->databaseError($e);
        }
    }

    /**
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

    /**
     * Evita que detalhes internos do banco sejam propagados
     * inadvertidamente para camadas superiores.
     *
     * O erro original deve ser enviado ao sistema de logs na camada
     * de infraestrutura, não apresentado ao usuário.
     *
     * @param Error $error
     * @return DatabaseError
     */
    private function databaseError(Error $error)
    {
        /*
         * Não usamos $error->getMessage() aqui, pois a mensagem pode
         * conter nomes de tabelas, constraints, SQL ou outros detalhes.
         */
        return new DatabaseError('Database operation failed');
    }
}

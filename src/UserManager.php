<?php

declare(strict_types=1);

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
use InvalidArgumentException;
use PDO;

/**
 * Base abstrata para componentes responsáveis pelo gerenciamento de usuários.
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

    private const DEFAULT_RANDOM_STRING_LENGTH = 24;
    private const CONFIRMATION_TOKEN_LENGTH = 32;
    private const CONFIRMATION_SELECTOR_LENGTH = 16;

    /** 24 horas. */
    private const CONFIRMATION_TTL = 86_400;

    /**
     * Limite alto o suficiente para passphrases, mas evita entradas gigantes
     * usadas para consumir CPU/memória durante o hashing.
     */
    private const MAX_PASSWORD_LENGTH = 2048;

    protected PdoDatabase $db;

    protected ?string $dbSchema;

    protected string $dbTablePrefix;

    /**
     * @param PdoDatabase|PdoDsn|PDO $databaseConnection
     */
    protected function __construct(
        $databaseConnection,
        ?string $dbTablePrefix = null,
        ?string $dbSchema = null
    ) {
        $this->db = self::createDatabaseConnection($databaseConnection);
        $this->dbSchema = $dbSchema;
        $this->dbTablePrefix = $dbTablePrefix ?? '';
    }

    /**
     * Cria uma string aleatória adequada para tokens e seletores.
     *
     * O valor retornado usa Base64 URL-safe.
     *
     * @throws InvalidArgumentException
     */
    public static function createRandomString(
        int $maxLength = self::DEFAULT_RANDOM_STRING_LENGTH
    ): string {
        if ($maxLength < 4 || $maxLength % 4 !== 0) {
            throw new InvalidArgumentException(
                'O tamanho deve ser um múltiplo de 4 e maior ou igual a 4'
            );
        }

        /*
         * Base64 converte aproximadamente 3 bytes em 4 caracteres.
         *
         * random_bytes() deve ser preferido a openssl_random_pseudo_bytes()
         * para geração de segredos e tokens.
         */
        $bytes = intdiv($maxLength, 4) * 3;

        return Base64::encodeUrlSafe(random_bytes($bytes));
    }

    /**
     * Cria um novo usuário.
     *
     * @throws InvalidEmailException
     * @throws InvalidPasswordException
     * @throws UserAlreadyExistsException
     * @throws DuplicateUsernameException
     * @throws AuthError
     */
    protected function createUserInternal(
        bool $requireUniqueUsername,
        string $email,
        string $password,
        ?string $username = null,
        ?callable $callback = null
    ): int {
        ignore_user_abort(true);

        $email = self::validateEmailAddress($email);
        $password = self::validatePassword($password, true);
        $username = self::normalizeUsername($username);

        if (
            $requireUniqueUsername
            && $username !== null
            && $this->usernameExists($username)
        ) {
            throw new DuplicateUsernameException();
        }

        /*
         * A senha em texto puro nunca deve ser armazenada.
         *
         * Assume-se que PasswordHash::from() utilize password_hash()
         * ou algoritmo equivalente seguro.
         */
        $passwordHash = PasswordHash::from($password);

        $verified = $callback === null ? 1 : 0;

        try {
            $this->db->insert(
                $this->makeTableNameComponents('users'),
                [
                    'email' => $email,
                    'password' => $passwordHash,
                    'username' => $username,
                    'verified' => $verified,
                    'registered' => time(),
                ]
            );
        } catch (IntegrityConstraintViolationException $e) {
            /*
             * A garantia definitiva contra duplicação deve estar no banco
             * através de uma UNIQUE CONSTRAINT sobre o e-mail.
             */
            throw new UserAlreadyExistsException();
        } catch (Error $e) {
            throw self::createDatabaseError($e);
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
     * Atualiza a senha de um usuário.
     *
     * @throws InvalidPasswordException
     * @throws UnknownIdException
     * @throws AuthError
     */
    protected function updatePasswordInternal(
        int $userId,
        string $newPassword
    ): void {
        /*
         * Valide ANTES de executar hashing.
         *
         * Isso também limita entradas excessivamente grandes.
         */
        $newPassword = self::validatePassword($newPassword, true);
        $passwordHash = PasswordHash::from($newPassword);

        try {
            $affected = $this->db->update(
                $this->makeTableNameComponents('users'),
                ['password' => $passwordHash],
                ['id' => $userId]
            );
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }

        if ($affected === 0) {
            throw new UnknownIdException();
        }
    }

    /**
     * Executado após uma autenticação bem-sucedida.
     */
    protected function onLoginSuccessful(
        int $userId,
        string $email,
        ?string $username,
        int $status,
        int $roles,
        int $forceLogout,
        bool $remembered
    ): void {
        /*
         * Mitiga session fixation.
         *
         * O ID antigo é invalidado e um novo ID é associado à sessão
         * autenticada.
         */
        Session::regenerate(true);

        $_SESSION[self::SESSION_FIELD_LOGGED_IN] = true;
        $_SESSION[self::SESSION_FIELD_USER_ID] = $userId;
        $_SESSION[self::SESSION_FIELD_EMAIL] = $email;
        $_SESSION[self::SESSION_FIELD_USERNAME] = $username;
        $_SESSION[self::SESSION_FIELD_STATUS] = $status;
        $_SESSION[self::SESSION_FIELD_ROLES] = $roles;
        $_SESSION[self::SESSION_FIELD_FORCE_LOGOUT] = $forceLogout;
        $_SESSION[self::SESSION_FIELD_REMEMBERED] = $remembered;
        $_SESSION[self::SESSION_FIELD_LAST_RESYNC] = time();

        /*
         * Remove qualquer estado temporário de autenticação em dois fatores.
         */
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_UNTIL] = null;
        $_SESSION[self::SESSION_FIELD_AWAITING_2FA_USER_ID] = null;
        $_SESSION[
            self::SESSION_FIELD_AWAITING_2FA_REMEMBER_DURATION
        ] = null;
    }

    /**
     * Retorna dados de usuário a partir do username.
     *
     * @throws UnknownUsernameException
     * @throws AmbiguousUsernameException
     * @throws AuthError
     */
    protected function getUserDataByUsername(
        string $username,
        array $requestedColumns
    ): array {
        $projection = self::buildSafeColumnProjection($requestedColumns);

        try {
            /*
             * LIMIT 2 é proposital.
             *
             * Não precisamos buscar todos os registros para descobrir se
             * há ambiguidade. Dois registros já são suficientes.
             */
            $users = $this->db->select(
                sprintf(
                    'SELECT %s FROM %s WHERE username = ? LIMIT 2',
                    $projection,
                    $this->makeTableName('users')
                ),
                [$username]
            );
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }

        $count = count($users);

        if ($count === 0) {
            throw new UnknownUsernameException();
        }

        if ($count > 1) {
            throw new AmbiguousUsernameException();
        }

        return $users[0];
    }

    /**
     * Valida e normaliza um endereço de e-mail.
     *
     * @throws InvalidEmailException
     */
    protected static function validateEmailAddress(string $email): string
    {
        $email = trim($email);

        if (
            $email === ''
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
        ) {
            throw new InvalidEmailException();
        }

        return $email;
    }

    /**
     * Valida uma senha.
     *
     * IMPORTANTE:
     * Não usamos trim() em senhas.
     *
     * Espaços podem fazer parte legitimamente da senha e modificá-los
     * silenciosamente reduz a entropia e pode impedir autenticações futuras.
     *
     * @throws InvalidPasswordException
     */
    protected static function validatePassword(
        string $password,
        ?bool $isNewPassword = null
    ): string {
        if ($password === '') {
            throw new InvalidPasswordException();
        }

        if (
            $isNewPassword === true
            && strlen($password) > self::MAX_PASSWORD_LENGTH
        ) {
            throw new InvalidPasswordException();
        }

        return $password;
    }

    /**
     * Cria uma solicitação de confirmação de e-mail.
     */
    protected function createConfirmationRequest(
        int $userId,
        string $email,
        callable $callback
    ): void {
        /*
         * Selector não precisa ser secreto, mas ainda deve ser imprevisível
         * para evitar enumeração e colisões.
         */
        $selector = self::createRandomString(
            self::CONFIRMATION_SELECTOR_LENGTH
        );

        /*
         * O token é o segredo.
         *
         * Somente seu hash será persistido no banco.
         */
        $token = self::createRandomString(
            self::CONFIRMATION_TOKEN_LENGTH
        );

        $tokenHash = TokenHash::from($token);

        try {
            $this->db->insert(
                $this->makeTableNameComponents('users_confirmations'),
                [
                    'user_id' => $userId,
                    'email' => $email,
                    'selector' => $selector,
                    'token' => $tokenHash,
                    'expires' => time() + self::CONFIRMATION_TTL,
                ]
            );
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }

        /*
         * Apenas o token original enviado ao usuário pode validar a
         * solicitação. O banco contém somente o hash.
         */
        $callback($selector, $token);
    }

    /**
     * Exclui uma diretiva "remember me".
     */
    protected function deleteRememberDirectiveForUserById(
        int $userId,
        ?string $selector = null
    ): void {
        $where = [
            'user' => $userId,
        ];

        if ($selector !== null) {
            $where['selector'] = $selector;
        }

        try {
            $this->db->delete(
                $this->makeTableNameComponents('users_remembered'),
                $where
            );
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }
    }

    /**
     * Força logout em todas as sessões pertencentes ao usuário.
     */
    protected function forceLogoutForUserById(int $userId): void
    {
        try {
            /*
             * Remove tokens persistentes antes de invalidar sessões.
             */
            $this->deleteRememberDirectiveForUserById($userId);

            $this->db->exec(
                sprintf(
                    'UPDATE %s
                     SET force_logout = force_logout + 1
                     WHERE id = ?',
                    $this->makeTableName('users')
                ),
                [$userId]
            );
        } catch (DatabaseError $e) {
            throw $e;
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }
    }

    /**
     * Monta os componentes de um nome de tabela.
     *
     * @return string[]
     */
    protected function makeTableNameComponents(string $name): array
    {
        if ($name === '') {
            return [];
        }

        $tableName = $this->dbTablePrefix . $name;

        if ($this->dbSchema === null || $this->dbSchema === '') {
            return [$tableName];
        }

        return [
            $this->dbSchema,
            $tableName,
        ];
    }

    /**
     * Retorna o nome completo de uma tabela.
     */
    protected function makeTableName(string $name): string
    {
        return implode(
            '.',
            $this->makeTableNameComponents($name)
        );
    }

    /**
     * Converte as diferentes formas suportadas de conexão para PdoDatabase.
     *
     * @param PdoDatabase|PdoDsn|PDO $databaseConnection
     */
    private static function createDatabaseConnection(
        $databaseConnection
    ): PdoDatabase {
        if ($databaseConnection instanceof PdoDatabase) {
            return $databaseConnection;
        }

        if ($databaseConnection instanceof PdoDsn) {
            return PdoDatabase::fromDsn($databaseConnection);
        }

        if ($databaseConnection instanceof PDO) {
            return PdoDatabase::fromPdo($databaseConnection, true);
        }

        throw new InvalidArgumentException(
            'A conexão deve ser uma instância de PdoDatabase, PdoDsn ou PDO'
        );
    }

    /**
     * Normaliza o username sem transformar string vazia em um nome válido.
     */
    private static function normalizeUsername(?string $username): ?string
    {
        if ($username === null) {
            return null;
        }

        $username = trim($username);

        return $username === '' ? null : $username;
    }

    /**
     * Verifica se já existe um usuário com o username.
     */
    private function usernameExists(string $username): bool
    {
        try {
            $count = $this->db->selectValue(
                sprintf(
                    'SELECT COUNT(*)
                     FROM %s
                     WHERE username = ?',
                    $this->makeTableName('users')
                ),
                [$username]
            );
        } catch (Error $e) {
            throw self::createDatabaseError($e);
        }

        return (int) $count > 0;
    }

    /**
     * Cria com segurança a lista de colunas da cláusula SELECT.
     *
     * Valores usados na projeção SQL não podem ser parametrizados através
     * de placeholders. Portanto, cada identificador precisa ser validado.
     */
    private static function buildSafeColumnProjection(
        array $columns
    ): string {
        if ($columns === []) {
            throw new InvalidArgumentException(
                'Ao menos uma coluna deve ser solicitada'
            );
        }

        foreach ($columns as $column) {
            if (
                !is_string($column)
                || preg_match(
                    '/^[A-Za-z_][A-Za-z0-9_]*$/D',
                    $column
                ) !== 1
            ) {
                throw new InvalidArgumentException(
                    'Nome de coluna SQL inválido'
                );
            }
        }

        return implode(', ', $columns);
    }

    /**
     * Converte erros da camada de banco na exceção pública da biblioteca.
     *
     * Evita repetir esse código em todos os métodos.
     */
    private static function createDatabaseError(Error $error): DatabaseError
    {
        /*
         * Não inclua parâmetros SQL, senha, token, cookie ou outros segredos
         * na mensagem lançada ou em logs.
         */
        return new DatabaseError($error->getMessage());
    }
}

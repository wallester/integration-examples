<?php

namespace Wallester\Example;

use Firebase\JWT\JWT;

class JwtTokenEncoder
{
    private const
        EXPIRATION = 30,
        ALGORITHM = 'RS256',
        SUBJECT = 'api-request';

    private string $issuer;
    private string $audience;

    /** @var resource  */
    private $privateKey;

    /** @var resource  */
    private $publicKey;

    /**
     * @param string $issuer
     * @param string $audience
     */
    public function __construct(string $issuer, string $audience)
    {
        $this->issuer = $issuer;
        $this->audience = $audience;
        $this->privateKey = openssl_pkey_get_private(
            file_get_contents(__DIR__ . '/../../../keys/example_private')
        );
        $this->publicKey = openssl_pkey_get_public(
            file_get_contents(__DIR__ . '/../../../keys/example_wallester_public')
        );
    }

    /**
     * @param string $body
     * @return string
     */
    public function createToken(string $body): string
    {
        $payload = [
            'iss' => $this->issuer,
            'aud' => $this->audience,
            'exp' => time() + self::EXPIRATION,
            'sub' => self::SUBJECT,
            'rbh' => base64_encode(hash('sha256', $body, true))
        ];

        return JWT::encode($payload, $this->privateKey, self::ALGORITHM);
    }

    /**
     * @param string $token
     * @return object
     */
    public function decode(string $token): object
    {
        return JWT::decode($token, $this->publicKey, [self::ALGORITHM]);
    }
}

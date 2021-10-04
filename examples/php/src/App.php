<?php

namespace Wallester\Example;

use Psr\Http\Message\ResponseInterface;

class App
{
    private JwtTokenEncoder $jwtTokenEncoder;
    private Api $api;

    public function __construct()
    {
        $this->jwtTokenEncoder = new JwtTokenEncoder($_ENV['ISSUER'], $_ENV['AUDIENCE']);
        $this->api = new Api($_ENV['API_URL']);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Exception
     */
    public function main(): void
    {
        $requestBody = json_encode(['message' => 'ping']);
        $this->outputString('Request Body: ' . $requestBody);

        $token = $this->jwtTokenEncoder->createToken($requestBody);
        $this->outputString('Request JWT token: ' . $token);

        $response = $this->api->ping($token, $requestBody);
        $this->outputString('Response Body: ' . $response->getBody());

        $this->verifyResponse($response);
        $this->outputString('Response is trusted');
    }

    /**
     * @param ResponseInterface $response
     * @return void
     * @throws \Exception
     */
    private function verifyResponse(ResponseInterface $response): void
    {
        $authorizationHeader = $response->getHeader('Authorization');
        $token = str_replace('Bearer ', '', $authorizationHeader[0] ?? null);
        if (!$token) {
            throw new \Exception('Expected token');
        }

        try {
            $this->jwtTokenEncoder->decode($token);
        } catch (\Throwable $e) {
            throw new \Exception('Response is not trusted: ' . $e->getMessage());
        }
    }

    /**
     * @param string $string
     */
    private function outputString(string $string): void
    {
        $string .= PHP_EOL;
        echo PHP_SAPI === 'cli' ? $string : nl2br($string);
    }
}

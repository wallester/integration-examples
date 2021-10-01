<?php

namespace Wallester\Example;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class Api
{
    private Client $client;

    /**
     * @param string $apiUrl
     */
    public function __construct(string $apiUrl)
    {
        $this->client = new Client([
            'base_uri' => $apiUrl,
            'headers' => [
                "Content-Type"  => 'application/json',
            ]
        ]);
    }

    /**
     * @param string $token
     * @param string $requestBody
     * @return ResponseInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function ping(string $token, string $requestBody): ResponseInterface
    {
        return $this->client->post('/v1/test/ping', [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
            ],
            'body' => $requestBody
        ]);
    }
}

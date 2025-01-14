<?php

declare(strict_types=1);

namespace Instagram\Transport;

use GuzzleHttp\Exception\ClientException;
use Instagram\Exception\InstagramFetchException;
use Instagram\Utils\Endpoints;
use Instagram\Utils\Proxy;
use Instagram\Utils\UserAgentHelper;
use Instagram\Utils\InstagramHelper;

class LocationData extends AbstractDataFeed
{
    /**
     * @param int $locationId
     *
     * @return \StdClass
     *
     * @throws InstagramFetchException
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function fetchData(int $locationId): \StdClass
    {
        $endpoint = Endpoints::getLocationUrl($locationId);

        $headers = [
            'headers' => [
                'user-agent' => UserAgentHelper::AGENT_DEFAULT,
            ],
            'cookies' => $this->session->getCookies(),
        ];

        if (!empty(Proxy::get())) {
            $headers['proxy'] = Proxy::get();
        }

        try {
            $res = $this->client->request('GET', $endpoint, $headers);
        } catch (ClientException $exception) {
            if ($exception->getCode() === 404) {
                throw new InstagramFetchException('Location ' . $locationId . ' not found');
            } else {
                throw new InstagramFetchException('Internal error');
            }
        }

        $html = (string)$res->getBody();

        preg_match('/<script type="text\/javascript">window\._sharedData\s?=(.+);<\/script>/', $html, $matches);

        if (!isset($matches[1])) {
            throw new InstagramFetchException('Unable to extract JSON data');
        }

        $data = json_decode($matches[1], false);

        return $data->entry_data->LocationsPage[0]->graphql->location;
    }

    /**
     * @param int $locationId
     * @param string $endCursor
     *
     * @return \StdClass
     *
     * @throws InstagramFetchException
     */
    public function fetchMoreData(int $locationId, string $endCursor): \StdClass
    {
        $endpoint = InstagramHelper::URL_BASE . 'explore/locations/' . $locationId . '/?__a=1&max_id=' . $endCursor;

        $data = $this->fetchJsonDataFeed($endpoint);

        return $data->graphql->location;
    }
}

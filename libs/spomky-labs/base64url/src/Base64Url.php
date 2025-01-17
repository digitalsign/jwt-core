<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
namespace Base64Url;

/**
 * Encode and decode data into Base64 Url Safe.
 */
final class Base64Url
{
    /**
     * @param string $data       The data to encode
     * @param bool   $usePadding If true, the "=" padding at end of the encoded value are kept, else it is removed
     *
     * @return string The data encoded
     */
    public static function encode($data, $usePadding = false)
    {
        $encoded = \strtr(\base64_encode($data), '+/', '-_');
        return true === $usePadding ? $encoded : \rtrim($encoded, '=');
    }
    /**
     * @param string $data The data to decode
     *
     * @throws \InvalidArgumentException
     *
     * @return string The data decoded
     */
    public static function decode($data)
    {
        $decoded = \base64_decode(\strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid data provided');
        }
        return $decoded;
    }
}
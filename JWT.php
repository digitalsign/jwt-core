<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

interface JWT
{
    /**
     * Returns the payload of the JWT.
     * null is a valid payload (e.g. JWS with detached payload).
     */
    public function getPayload();
}

<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Tests;

use Jose\Component\Core\Algorithm;

class FooAlgorithm implements Algorithm
{
    public function name()
    {
        return 'foo';
    }
    public function allowedKeyTypes()
    {
        return ['FOO'];
    }
}

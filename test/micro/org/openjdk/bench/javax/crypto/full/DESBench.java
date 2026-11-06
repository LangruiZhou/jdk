/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package org.openjdk.bench.javax.crypto.full;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Setup;

public class DESBench extends CryptoBase {
    public static final int SET_SIZE = 128;

    @Param({"DES/ECB/NoPadding", "DES/ECB/PKCS5Padding",
            "DES/CBC/NoPadding", "DES/CBC/PKCS5Padding"})
    private String algorithm;

    @Param({"8", "16", "32", "64", "256", "1024", "4096", "8192", "16384"})
    private int dataSize;

    private byte[][] data;
    private byte[][] encryptedData;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private int index;

    @Setup
    public void setup() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException, InvalidParameterSpecException {
        setupProvider();
        SecretKeySpec key = new SecretKeySpec(fillSecureRandom(new byte[8]), "DES");
        encryptCipher = makeCipher(prov, algorithm);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        decryptCipher = makeCipher(prov, algorithm);
        decryptCipher.init(Cipher.DECRYPT_MODE, key, encryptCipher.getParameters());
        data = fillRandom(new byte[SET_SIZE][dataSize]);
        encryptedData = fillEncrypted(data, encryptCipher);
    }

    @Benchmark
    public byte[] encrypt() throws BadPaddingException, IllegalBlockSizeException {
        byte[] value = data[index];
        index = (index + 1) % SET_SIZE;
        return encryptCipher.doFinal(value);
    }

    @Benchmark
    public byte[] decrypt() throws BadPaddingException, IllegalBlockSizeException {
        byte[] value = encryptedData[index];
        index = (index + 1) % SET_SIZE;
        return decryptCipher.doFinal(value);
    }
}

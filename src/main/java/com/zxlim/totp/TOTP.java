/**
 * Copyright 2017 (c) Zhao Xiang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.zxlim.totp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

public class TOTP {
	
	private final int window;
	private final byte[] secret;
	private final String secretEncoded;

	private static final int secret_size_bits = 160;
	
	private static final String HMAC_ALGORITHM = "HmacSHA1";
	private static final String HMAC_PROVIDER = "SunJCE";

	private TOTP(
		final int window,
		final byte[] secret,
		final String secretEncoded
	) {
		this.window = window;
		this.secret = secret;
		this.secretEncoded = secretEncoded;
	}

	public static final TOTP getInstance(
		final int window,
		final String encodedSecret
	)
		throws IllegalWindowSizeException 
	{
		if (window >= 1 && window <= 10) {
			
			Base32 base32 = new Base32();
			final byte[] secret = base32.decode(encodedSecret);
			return new TOTP(window, secret, encodedSecret);
			
		} else {
			throw new IllegalWindowSizeException("Window size provided not allowed: " + window);
		}
	}

	public static final TOTP getInstance(
		final String encodedSecret
	) {
		Base32 base32 = new Base32();
		final byte[] secret = base32.decode(encodedSecret);
		return new TOTP(3, secret, encodedSecret);
	}

	public static final String generateSecret() {
		Base32 base32 = new Base32();
		SecureRandom random = null;
		final byte[] secret = new byte[secret_size_bits / 8];

		try {
			random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (
			NoSuchAlgorithmException |
			NoSuchProviderException e
		) {
			return null;
		}

		random.nextBytes(secret);

		return new String (base32.encode(secret));
	}
	
	public final String getQRCodeURL(
		String issuer,
		String user
	) {
		if (issuer.contains(":") || user.contains(":")) {
			System.err.println("Issuer name or username contains an illegal character.");
			return null;
		}

		//Remove all whitespace
		issuer = issuer.trim().replaceAll("\\s", "");
		user = user.trim().replaceAll("\\s", "");
		
		final String url_format = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s:%s%%3Fsecret=%s";
		return String.format(url_format, issuer, user, secretEncoded);
	}

	public final boolean verifyCode(
		final long code
	) {
		final long time = (System.currentTimeMillis() / 1000) / 30;

		for (int i = -window; i <= window; ++i) {
			if (generateTOTP(time, i) == code) {
				return true;
			}
		}

		return false;
	}

	private final long generateTOTP(
		final long time,
		final long count
	) {
		long truncatedResult = 0L;
		long val = time + count;
		final byte[] buf = new byte[8];

		for (int i = 8; i-- > 0; val >>>= 8) {
			buf[i] = (byte) val;
		}

		final byte[] result = hmac(buf);

		final int offset = result[result.length - 1] & 0xF;

		for (int i = 0; i < 4; ++i) {
			truncatedResult = (truncatedResult << 8) | (result[offset + i] & 0xFF);
		}
		
		return ((truncatedResult & 0x7FFFFFFF) % 1000000);
	}

	private final byte[] hmac(
		final byte[] data
	) {
		final Mac mac;

		try {
			mac = Mac.getInstance(HMAC_ALGORITHM, HMAC_PROVIDER);
		} catch (
			NoSuchAlgorithmException |
			NoSuchProviderException e
		) {
			return null;
		}

		try {
			mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
		} catch (
			InvalidKeyException e
		) {
			return null;
		}

		return mac.doFinal(data);
	}
}

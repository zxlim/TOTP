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

package com.zxlim.test;

import java.util.Scanner;

import com.zxlim.totp.IllegalWindowSizeException;
import com.zxlim.totp.TOTP;

public class Test {
	
	private static final Scanner s = new Scanner(System.in);
	
	public static void main(
		String[] args
	) {
		int choice = -1;
		
		System.out.println("Actions:");
		System.out.println("[1] Generate OTP Secret.");
		System.out.println("[2] Verify OTP.");
		
		System.out.print("Action: ");
		final String option = s.nextLine();
		System.out.println();
		
		try {
			choice = Integer.parseInt(option);
		} catch (
			NumberFormatException e
		) {
			System.err.println("Invalid option");
		}
		
		switch (choice) {
			case 1:
				final String secret = TOTP.generateSecret();
				System.out.println("Secret:\t" + secret);
				final TOTP auth = TOTP.getInstance(secret);
				System.out.println("QR Code: " + auth.getQRCodeURL("JavaTOTP", "zxlim"));
				verify(secret);
				break;
			case 2:
				System.out.print("Secret: ");
				final String userSecret = s.nextLine();
				verify(userSecret);
				break;
			default:
				System.err.println("Invalid option");
				break;
		}
		
		s.close();
	}
	
	private static void verify(
		final String secret
	) {
		long code = 0;
		
		System.out.print("Code: ");
		final String codeStr = s.nextLine();
		
		try {
			code = Long.parseLong(codeStr);
		} catch (
			NumberFormatException e
		) {
			System.err.println("Invalid code.");
			return;
		}
		
		TOTP auth = null;
		
		try {
			auth = TOTP.getInstance(3, secret);
		} catch (
			IllegalWindowSizeException e
		) {
			e.printStackTrace();
			return;
		}
		
		if (auth.verifyCode(code)) {
			System.out.println("Verification successful.");
		} else {
			System.err.println("Invalid code.");
		}
		
		return;
	}
}

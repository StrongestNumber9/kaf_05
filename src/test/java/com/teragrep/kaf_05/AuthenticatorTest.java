/*
 * Teragrep Authentication Module for Apache Kafka (kaf_05)
 * Copyright (C) 2019-2026 Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.kaf_05;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AuthenticatorTest {

    @Test
    public void testWriterAuthenticationSuccess() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json", ""
                );
        Assertions.assertTrue(tcach.authenticate("writer", "writer-password".toCharArray()));
    }

    @Test
    public void testClientAuthenticationSuccess() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json", ""
                );
        Assertions
                .assertTrue(tcach.authenticate("trusted-5", "nPBSgvBZVGRQ2Zu8TKItH9bElr0eaosYC0n6BTPqlok".toCharArray()));
    }

    @Test
    public void testClusterAuthenticationSuccess() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json", ""
                );
        Assertions.assertTrue(tcach.authenticate("cluster-user", "cluster-password".toCharArray()));
    }

    @Test
    public void testAuthenticationFail() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json", ""
                );
        Assertions.assertFalse(tcach.authenticate("trusted-5", "my incorrect password".toCharArray()));
    }

    @Test
    public void testAuthenticationNotfound() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json", ""
                );
        Assertions.assertFalse(tcach.authenticate("no-user", "no-password".toCharArray()));
    }

    @Test
    public void testClientAuthenticationSuccessWithDomain() {
        TeragrepAuthenticateCallbackHandler tcach = new TeragrepAuthenticateCallbackHandler();
        tcach
                .configure(
                        "src/test/resources/credentials.domain-tld.json", "src/test/resources/credentials.writer.json",
                        "src/test/resources/credentials.cluster.json",
                        "src/test/resources/identitySuffix.domain-tld.json"
                );
        Assertions
                .assertTrue(tcach.authenticate("trusted-5", "nPBSgvBZVGRQ2Zu8TKItH9bElr0eaosYC0n6BTPqlok".toCharArray()));
    }
}

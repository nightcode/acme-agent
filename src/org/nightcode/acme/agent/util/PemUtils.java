/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.nightcode.acme.agent.util;

import java.io.IOException;
import java.io.Reader;
import java.security.KeyPair;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public enum PemUtils {
  ;

  private static final JcaPEMKeyConverter JCA_PEM_KEY_CONVERTER = new JcaPEMKeyConverter();

  public static KeyPair readKeyPair(Reader reader) throws IOException {
    Object object;
    try (PEMParser parser = new PEMParser(reader)) {
      object = parser.readObject();
    }
    return switch (object) {
      case PEMKeyPair pemKeyPair -> JCA_PEM_KEY_CONVERTER.getKeyPair(pemKeyPair);
      case PrivateKeyInfo privateKeyInfo -> new KeyPair(JCA_PEM_KEY_CONVERTER.getPublicKey(createPublicKeyInfo(privateKeyInfo)),
                                                        JCA_PEM_KEY_CONVERTER.getPrivateKey(privateKeyInfo));
      case null -> throw new IOException("no PEM object found, expected a private key");
      default -> throw new IOException("unexpected PEM object " + object.getClass().getName() + ", expected a private key");
    };
  }

  private static SubjectPublicKeyInfo createPublicKeyInfo(PrivateKeyInfo privateKeyInfo) throws IOException {
    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(privateKeyInfo);

    AsymmetricKeyParameter publicKey;
    if (privateKey instanceof RSAPrivateCrtKeyParameters rsa) {
      publicKey = new RSAKeyParameters(false, rsa.getModulus(), rsa.getPublicExponent());
    } else if (privateKey instanceof ECPrivateKeyParameters ec) {
      ECDomainParameters domain = ec.getParameters();
      publicKey = new ECPublicKeyParameters(new FixedPointCombMultiplier().multiply(domain.getG(), ec.getD()).normalize(), domain);
    } else {
      throw new IOException("unsupported private key type: " + privateKey.getClass().getName());
    }

    return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey);
  }
}

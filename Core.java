package lorentealberto.byss.csimetrico;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author Alberto Escribano Lorente
 */
public class Core {
   
    public boolean desencriptar(File file, char[] password) {
        // Cargar cabecera
        Header h = new Header();
        try (FileInputStream fis = new FileInputStream(file)) {
            if (h.load(fis)) {
                String algoritmo = h.getAlgorithm();
                
                // Cargar componentes básicos
                PBEKeySpec keySpec = new PBEKeySpec(password);
                PBEParameterSpec parameterSpec = new PBEParameterSpec(h.getSalt(), Settings.COUNT);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algoritmo);
                SecretKey key = keyFactory.generateSecret(keySpec);
                Cipher c = Cipher.getInstance(algoritmo);
                c.init(Cipher.DECRYPT_MODE, key, parameterSpec);
                
                // Flujo de entrada desencriptado
                CipherInputStream cis = new CipherInputStream(fis, c);
                
                // Flujo de salida
                String path = file.getAbsolutePath();
                path = path.substring(0, path.lastIndexOf("."));
                FileOutputStream decoded = new FileOutputStream(path);
                
                int container;
                while ((container = cis.read()) != -1)
                    decoded.write(container);
                decoded.flush();
                
                decoded.close();
                cis.close();
                fis.close();
                return true;
            }
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
        
    }
    
    public boolean encriptar(File file, char[] password, String algoritmo) {
        try {
            // Iniciar componentes básicos
            PBEKeySpec keySpec = new PBEKeySpec(password);
            PBEParameterSpec parameterSpec = new PBEParameterSpec(Settings.SALT, Settings.COUNT);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algoritmo);
            SecretKey key = keyFactory.generateSecret(keySpec);
            Cipher c = Cipher.getInstance(algoritmo);
            c.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            
            // Cabecera
            Header header = new Header(algoritmo, Settings.SALT);
            
            // Archivo encriptado
            File encrypted = new File(file.getPath() + ".algiz");
            
            FileInputStream fis;
            // Encripta y escribe
            try ( // Flujo de salida
                    FileOutputStream output = new FileOutputStream(encrypted); // Encripta y escribe
                    CipherOutputStream cos = new CipherOutputStream(output, c)) {
                // Flujo de entrada
                fis = new FileInputStream(file);
                // Guarda la cabezera
                header.save(output);
                /** Traspasa el contenido del fichero original a un fichero encriptado*/
                int content;
                while ((content = fis.read()) != -1)
                    cos.write(content);
                // Fuerza a guardar los bytes
                cos.flush();
                fis.close();
                return true;
            }
            
            // Cierra el flujo de entrada
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | FileNotFoundException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Core.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
}

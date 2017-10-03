package lorentealberto.byss.csimetrico;
/**
 * <p>Título: BySSLab</p>
 * <p>Descripción: Pr�cticas de BySS</p>
 * <p>Copyright: Copyright (c) 2014</p>
 * <p>Empresa: DISIT de la UEx</p>
 * <p>Nueva version, para PBE</p>
 * @author Lorenzo M. Martínez Bravo
 * @version 1.0
 */
import java.io.*;

/**
 * Clase para la gestión de la cabecera que se añade los ficheros cifrados.
 * Permite gestionar los diferentes atributos que se almacenan:
 * -Máscara
 * -Algoritmo
 * -Salt   
 */
public class Header {
  private final static byte MARK[]= {1,2,3,4,5,6,7,8,9,0};
  private final static byte MARKLENGTH = 10;
  private final static byte SALTLENGTH = 8;
  private final static byte HEADERLENGTH = MARKLENGTH+SALTLENGTH+1;
  private final static String algorithms[] = {"PBEWithMD5AndDES", "PBEWithMD5AndTripleDES",
	  							"PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40"};
  private
  /**
   * Algoritmo de cifrado codificado segun los valores de 'algorithms'  
   */
  	String algorithm;
  /**
   * Salt para el cifrado: array de bytes.  
   */
  	byte salt[];

  /**
   * Constructor por omision. Inicia los atributos con valores por omision:
   * -Algoritmo:   PBEWithMD5AndDES
   * -Salt fija:   {0x7d, 0x60, 0x43, 0x5f, 0x02, 0xe9, 0xe0, 0xae} 
   */
  public Header() {
    algorithm = "PBEWithMD5AndDES";
    salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };	
  }
  /**
   * Constructor. Inicia los atributos con valores suministrados.
   * @param algorithm - nombre est�ndar del algoritmo elegido
   * @param salt - Semilla elegida 
   */
  public Header(String algorithm, byte[] salt) {
     this.algorithm = algorithm;
     this.salt = salt;
  }
  
  public String getAlgorithm(){
    return algorithm;
  }
  
  public byte[] getSalt(){
	    return salt;
  }
  
  /**
   * Intenta cargar los datos de una cabecera desde un InputStream abierto.   
   * Si tiene exito, los datos quedan en la clase.
   * @param r el InputStream abierto
   * @return true si la carga es correcta, false en otro caso
   */
  public boolean load(InputStream r){
    byte buf[] = new byte[HEADERLENGTH];
    boolean breturn=false;
    try {
      if(r.read(buf,0,HEADERLENGTH)==HEADERLENGTH) {
        byte i=0;
        while((i<MARKLENGTH) && (buf[i]==MARK[i])) i++;
        if (i==MARKLENGTH) {
          algorithm = algorithms[buf[i]];
          salt = new byte[SALTLENGTH];
          System.arraycopy(buf, i+1, salt, 0, SALTLENGTH);          
          breturn = true;
        }
      }
    }
    catch (IOException e) {
    }
    return breturn;
  }
  
  /**
   * Intenta guardar la cabecera actual en un OutputStream abierto.   
   * 
   * @param fos el OutputStream abierto
   * @return true si tiene exito, false en otro caso
   */
  public boolean save(OutputStream fos){
    boolean breturn=false;
    try {
      fos.write(MARK);
      fos.write(search(algorithms,algorithm));
      fos.write(salt);      
      fos.flush();
      breturn = true;
    }
    catch (IOException e) {
    }
    return breturn;
  }

  private int search(String a[], String m) {
    int i;
    for(i=a.length-1; i!=-1; i--)
      if(a[i].compareTo(m)==0) break;
    return i;
  }
  /**
   * Prueba el funcionamiento de la clase, creando una cabecera, guardandola en un   
   * fichero y recuperandola posteriomente.
   * 
   */
  public static void test() {
    try {
    Header fh = new Header();
        try (FileOutputStream fos = new FileOutputStream("fileheader.prueba")) {
            fh.save(fos);
        }

    Header fh2= new Header();
        try (FileInputStream fis = new FileInputStream("fileheader.prueba")) {
            if (fh2.load(fis)){
                System.out.println("Le�do, Algoritmo: "+fh2.getAlgorithm());
                System.out.print  ("Le�do, Salt     : ");
                for(byte i=0;i<SALTLENGTH;i++)
                    System.out.print(String.format("0x%h ", fh2.getSalt()[i]));
            }
            else
                System.out.println("Error en la carga");
        }
    }
    catch (IOException e) {}
  }

  public static void main(String args[]){
	  test();
  }
  
}//Header
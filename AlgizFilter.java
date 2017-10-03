package lorentealberto.byss.csimetrico;

import java.io.File;

/**
 *
 * @author Alberto Escribano Lorente
 */
public class AlgizFilter extends javax.swing.filechooser.FileFilter{
    @Override
    public boolean accept(File file) {
        return file.isDirectory() || file.getAbsolutePath().endsWith(".algiz");
    }
    @Override
    public String getDescription() {
        return "Archivo protegido (*.algiz)";
    }
}

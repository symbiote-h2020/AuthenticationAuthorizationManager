package eu.h2020.symbiote.security.services;

import eu.h2020.symbiote.security.commons.VirtualFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.io.ZipOutputStream;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.util.Zip4jConstants;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Spring service to provide zip output streams.
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 */
@Service
public class ZipService {
    public void zip(List<VirtualFile> virtualFiles, OutputStream outputStream) throws ZipException, IOException {
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(outputStream)) {
            for (VirtualFile virtualFile : virtualFiles) {
                ZipParameters dataFileParameters = new ZipParameters();
                dataFileParameters.setCompressionMethod(Zip4jConstants.COMP_DEFLATE);
                dataFileParameters.setCompressionLevel(Zip4jConstants.DEFLATE_LEVEL_NORMAL);
                dataFileParameters.setFileNameInZip(virtualFile.getFilename());
                dataFileParameters.setSourceExternalStream(true);
                zipOutputStream.putNextEntry(null, dataFileParameters);
                IOUtils.copy(virtualFile.getInputStream(), zipOutputStream);
                zipOutputStream.closeEntry();
            }
            zipOutputStream.finish();
        }
    }
}

package eu.h2020.symbiote.security.commons;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.InputStream;

@Getter @Setter @AllArgsConstructor
public class VirtualFile {

    private InputStream inputStream;
    private String filename;

}

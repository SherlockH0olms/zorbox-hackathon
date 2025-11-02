package com.webapp.backend_nexora.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.Set;

@Service
public class FileValidationService {
    private static final Set<String> PASSWORD_REQUIRED_EXTENSIONS = Set.of(
            "exe", "dll", "ps1", "js", "docx", "xls", "ppt", "zip", "rar", "7z"
    );

    public void validate(MultipartFile file, String password) {
        String extension = getExtension(file.getOriginalFilename());
        if (PASSWORD_REQUIRED_EXTENSIONS.contains(extension) &&
                (password == null || password.isBlank())) {
            throw new IllegalArgumentException("Password required for " + extension + " files");
        }
    }

    private String getExtension(String fileName) {
        if (fileName == null || !fileName.contains(".")) return "";
        return fileName.substring(fileName.lastIndexOf('.') + 1).toLowerCase();
    }
}

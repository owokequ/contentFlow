package com.owoke.contentflow;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest
@AutoConfigureMockMvc
public abstract class PostgresIntegrationTest {
    // One isolated container for the shared Spring test context; Ryuk removes it after the JVM exits.
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17");
    private static final java.nio.file.Path KEY_DIRECTORY;

    static {
        try {
            KEY_DIRECTORY = java.nio.file.Files.createTempDirectory("contentflow-test-jwt-");
            var generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            writePem(KEY_DIRECTORY.resolve("private.pem"), "PRIVATE KEY", pair.getPrivate().getEncoded());
            writePem(KEY_DIRECTORY.resolve("public.pem"), "PUBLIC KEY", pair.getPublic().getEncoded());
        } catch (Exception ex) { throw new ExceptionInInitializerError(ex); }
        POSTGRES.start();
    }

    private static void writePem(java.nio.file.Path path, String type, byte[] bytes) throws Exception {
        java.nio.file.Files.writeString(path, "-----BEGIN " + type + "-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n");
        path.toFile().deleteOnExit();
    }

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.config.import", () -> "");
        registry.add("identity.tokens.private-key", () -> KEY_DIRECTORY.resolve("private.pem").toUri().toString());
        registry.add("identity.tokens.public-key", () -> KEY_DIRECTORY.resolve("public.pem").toUri().toString());
        registry.add("identity.tokens.cookie-secure", () -> "true");
        registry.add("identity.tokens.allowed-origins", () -> "http://localhost:3000");
    }
}

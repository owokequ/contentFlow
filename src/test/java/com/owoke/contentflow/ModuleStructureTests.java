package com.owoke.contentflow;

import org.junit.jupiter.api.Test;
import org.springframework.modulith.core.ApplicationModules;

class ModuleStructureTests {
    @Test
    void moduleDependenciesRespectPublicInterfaces() {
        ApplicationModules.of(ContentflowApplication.class).verify();
    }
}

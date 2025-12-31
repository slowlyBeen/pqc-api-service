package com.github.slowlybeen.pqc;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
        "security.allowed-ips=127.0.0.1,0:0:0:0:0:0:0:1",
        "pqc.pool.kem-size=5",
        "pqc.pool.dsa-size=5",
        "pqc.pool.refill-interval=10000"
})
class PqcApiServiceApplicationTests {

    @Test
    void contextLoads() {
    }
}
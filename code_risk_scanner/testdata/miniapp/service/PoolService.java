package service;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PoolService {
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd");

    public void submit() {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        pool.submit(() -> SDF.format(new Date()));
    }

    public String load() throws Exception {
        return CompletableFuture.supplyAsync(() -> "ok").get();
    }
}

package me.lain;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.atomic.AtomicInteger;

public class Program {

    static final int TotalTasks = 2;
    static final int MaxRetries = 5;
    static final String StevenBlack = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
    static final String LocalForwards = "https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf";
    static final AtomicInteger CompletedTasks = new AtomicInteger();

    public static void main(String[] args) {
        List<ForkJoinTask<?>> tasks = new ArrayList<>();
        tasks.add(ForkJoinTask.adapt(Program::processStevenBlack));
        tasks.add(ForkJoinTask.adapt(Program::processLocalForwards));
        ForkJoinTask.invokeAll(tasks);
        if (CompletedTasks.get() != TotalTasks)
            System.exit(1);
    }

    static void process(Path in, Path out, Processor processor) throws IOException {
        System.out.printf("> Processing %s%n", in);
        try (BufferedReader rIn = Files.newBufferedReader(in); BufferedWriter wOut = Files.newBufferedWriter(out)) {
            processor.accept(rIn, wOut);
        }
        System.out.printf("> Completed %s%n", out);
    }

    static void processStevenBlack() {
        resource(StevenBlack).flatMap(remote -> read(remote, Paths.get("StevenBlack"))).ifPresent(local -> {
            try {
                process(local, Paths.get("StevenBlack_Processed"), (r, w) -> {
                    String line;
                    while ((line = r.readLine()) != null) {
                        if (line.isEmpty() || line.startsWith("#"))
                            continue;
                        int indexOfSpace = line.indexOf(" ");
                        if (indexOfSpace == -1)
                            continue;
                        String ip = line.substring(0, indexOfSpace).trim();
                        String host = line.substring(indexOfSpace + 1).trim();
                        int indexOfComment = host.indexOf("#");
                        if (indexOfComment != -1)
                            host = host.substring(0, indexOfComment).trim();
                        if (!"0.0.0.0".equals(ip) || "0.0.0.0".equals(host))
                            continue;
                        w.write("local-zone: ");
                        w.write(host);
                        w.write(" redirect");
                        w.newLine();
                        w.write("local-data: \"");
                        w.write(host);
                        w.write(" A 0.0.0.0\"");
                        w.newLine();
                    }
                });
                CompletedTasks.getAndIncrement();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    static void processLocalForwards() {
        resource(LocalForwards).flatMap(remote -> read(remote, Paths.get("LocalForwards"))).ifPresent(local -> {
            try {
                process(local, Paths.get("LocalForwards_Processed"), (r, w) -> {
                    String line;
                    while ((line = r.readLine()) != null) {
                        if (line.isEmpty() || line.startsWith("#"))
                            continue;
                        String[] al = line.split("/", 3);
                        w.write("forward-zone:");
                        w.newLine();
                        w.write("  name: \"");
                        w.write(al[1]);
                        w.write("\"");
                        w.newLine();
                        w.write("  forward-addr: 114.114.114.114");
                        w.newLine();
                    }
                });
                CompletedTasks.getAndIncrement();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    static Optional<Path> read(URL resource, Path local) {
        int tries = 0;
        while (tries++ < MaxRetries) {
            System.out.printf("> Downloading %s (%d/%d)%n", resource, tries, MaxRetries);
            try (FileChannel channel = FileChannel.open(local, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                URLConnection conn = resource.openConnection();
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(30000);
                conn.setUseCaches(false);
                conn.setDoInput(true);
                conn.setDoOutput(false);
                channel.transferFrom(Channels.newChannel(conn.getInputStream()), 0L, Long.MAX_VALUE);
                return Optional.of(local);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return Optional.empty();
    }

    static Optional<URL> resource(String resource) {
        try {
            return Optional.of(new URL(resource));
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }

    interface Processor {

        void accept(BufferedReader in, BufferedWriter out) throws IOException;

    }

}

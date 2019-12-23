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

public class Program
{

    interface Processor
    {

        void accept(BufferedReader in, BufferedWriter out) throws IOException;

    }

    static final int MaxRetries = 5;
    static final String AdServers = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=1&startdate%5Bday%5D=&startdate%5Bmonth%5D=&startdate%5Byear%5D=";
    static final String MalwareDomains = "https://mirror1.malwaredomains.com/files/BOOT";
    static final String LocalForwards = "https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf";
    static final AtomicInteger CompletedTasks = new AtomicInteger();

    public static void main(String[] args)
    {
        List<ForkJoinTask<?>> tasks = new ArrayList<>();
        tasks.add(ForkJoinTask.adapt(Program::processAdServers));
        tasks.add(ForkJoinTask.adapt(Program::processMalwareDomains));
        tasks.add(ForkJoinTask.adapt(Program::processLocalForwards));
        ForkJoinTask.invokeAll(tasks);
        if (CompletedTasks.get() != 3)
            System.exit(1);
    }

    static void process(Path in, Path out, Processor processor) throws IOException
    {
        System.out.println(String.format("> Processing %s", in));
        try (BufferedReader rIn = Files.newBufferedReader(in); BufferedWriter wOut = Files.newBufferedWriter(out))
        {
            processor.accept(rIn, wOut);
        }
        System.out.println(String.format("> Completed %s", out));
    }

    static void processAdServers()
    {
        resource(AdServers)
                .ifPresent(remote -> read(remote, Paths.get("AdServers"), MaxRetries)
                        .ifPresent(local -> {
                            try
                            {
                                process(local, Paths.get("AdServers_Processed"), (r, w) -> {
                                    String l = null;
                                    while ((l = r.readLine()) != null)
                                    {
                                        if (l.isEmpty())
                                            continue;
                                        w.write("local-zone: ");
                                        w.write(l);
                                        w.write(" redirect");
                                        w.newLine();
                                        w.write("local-data: \"");
                                        w.write(l);
                                        w.write(" A 0.0.0.0\"");
                                        w.newLine();
                                    }
                                });
                                CompletedTasks.getAndIncrement();
                            }
                            catch (IOException e)
                            {
                                e.printStackTrace();
                            }
                        }));
    }

    static void processLocalForwards()
    {
        resource(LocalForwards)
                .ifPresent(remote -> read(remote, Paths.get("LocalForwards"), MaxRetries)
                        .ifPresent(local -> {
                            try
                            {
                                process(local, Paths.get("LocalForwards_Processed"), (r, w) -> {
                                    String l = null;
                                    while ((l = r.readLine()) != null)
                                    {
                                        if (l.isEmpty() || l.startsWith("#"))
                                            continue;
                                        String[] al = l.split("/", 3);
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
                            }
                            catch (IOException e)
                            {
                                e.printStackTrace();
                            }
                        }));
    }

    static void processMalwareDomains()
    {
        resource(MalwareDomains)
                .ifPresent(remote -> read(remote, Paths.get("MalwareDomains"), MaxRetries)
                        .ifPresent(local -> {
                            try
                            {
                                process(local, Paths.get("MalwareDomains_Processed"), (r, w) -> {
                                    String l = null;
                                    while ((l = r.readLine()) != null)
                                    {
                                        if (l.isEmpty() || l.startsWith("/"))
                                            continue;
                                        String[] al = l.split(" ", 3);
                                        w.write("local-zone: ");
                                        w.write(al[1]);
                                        w.write(" redirect");
                                        w.newLine();
                                        w.write("local-data: \"");
                                        w.write(al[1]);
                                        w.write(" A 0.0.0.0\"");
                                        w.newLine();
                                    }
                                });
                                CompletedTasks.getAndIncrement();
                            }
                            catch (IOException e)
                            {
                                e.printStackTrace();
                            }
                        }));
    }

    static Optional<Path> read(URL resource, Path local, int maxTries)
    {
        int tries = 0;
        while (tries++ < maxTries)
        {
            System.out.println(String.format("> Downloading %s (%d/%d)", resource, tries, maxTries));
            try (FileChannel channel = FileChannel.open(local, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))
            {
                URLConnection conn = resource.openConnection();
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(30000);
                conn.setUseCaches(false);
                conn.setDoInput(true);
                conn.setDoOutput(false);
                channel.transferFrom(Channels.newChannel(conn.getInputStream()), 0L, Long.MAX_VALUE);
                return Optional.of(local);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            finally
            {
                if (Thread.interrupted())
                {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return Optional.empty();
    }

    static Optional<URL> resource(String resource)
    {
        try
        {
            return Optional.of(new URL(resource));
        }
        catch (MalformedURLException e)
        {
            e.printStackTrace();
            return Optional.empty();
        }
    }

}

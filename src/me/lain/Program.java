package me.lain;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public class Program
{

    static void loadDB()
    {
        System.out.println("loading database");
        try
        {
            if (db_file.exists())
                db.load(new FileInputStream(db_file));
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        System.out.println("loaded database with " + db.size() + (db.size() == 1 ? " entry" : " entries"));
    }

    public static void main(String[] args)
    {
        loadDB();

        processAdServers();
        processMalwareDomains();
        processLocalForwards();
    }

    static void processAdServers()
    {
        File f = new File("AdServers");
        File o = new File("AdServers_Processed");
        BufferedReader r = null;
        try
        {
            r = new BufferedReader(new InputStreamReader(readRemoteFile(f, new URL("http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=1&startdate%5Bday%5D=&startdate%5Bmonth%5D=&startdate%5Byear%5D="), Proxy.NO_PROXY, 3, code -> true)));

            BufferedWriter w = null;
            try
            {
                w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(o)));
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
            }
            finally
            {
                if (w != null)
                    try
                    {
                        w.close();
                    }
                    catch (IOException e)
                    {
                    }
            }
        }
        catch (IOException e)
        {
        }
        finally
        {
            if (r != null)
                try
                {
                    r.close();
                }
                catch (IOException e)
                {
                }
        }
    }

    static void processMalwareDomains()
    {
        File f = new File("MalwareDomains");
        File o = new File("MalwareDomains_Processed");
        BufferedReader r = null;
        try
        {
            r = new BufferedReader(new InputStreamReader(readRemoteFile(f, new URL("http://mirror1.malwaredomains.com/files/BOOT"), Proxy.NO_PROXY, 3, code -> true)));

            BufferedWriter w = null;
            try
            {
                w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(o)));
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
            }
            finally
            {
                if (w != null)
                    try
                    {
                        w.close();
                    }
                    catch (IOException e)
                    {
                    }
            }
        }
        catch (IOException e)
        {
        }
        finally
        {
            if (r != null)
                try
                {
                    r.close();
                }
                catch (IOException e)
                {
                }
        }
    }

    static void processLocalForwards()
    {
        File f = new File("LocalForwards");
        File o = new File("LocalForwards_Processed");
        BufferedReader r = null;
        try
        {
            r = new BufferedReader(new InputStreamReader(readRemoteFile(f, new URL("https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf"), Proxy.NO_PROXY, 3, code -> true)));

            BufferedWriter w = null;
            try
            {
                w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(o)));
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
            }
            finally
            {
                if (w != null)
                    try
                    {
                        w.close();
                    }
                    catch (IOException e)
                    {
                    }
            }
        }
        catch (IOException e)
        {
        }
        finally
        {
            if (r != null)
                try
                {
                    r.close();
                }
                catch (IOException e)
                {
                }
        }
    }

    static Map<String, String> parseField(String field)
    {
        return Pattern.compile(",").splitAsStream(field == null ? "" : field).map(String::trim).collect(HashMap::new, (m, s) -> {
            String[] as = s.split("=", 2);
            m.put(as[0], as.length == 2 ? as[1] : null);
        }, HashMap::putAll);
    }

    static InputStream readRemoteFile(File local, URL remote, Proxy proxy, int maxTries, Predicate<Integer> handleErrorCode)
    {
        if (local.exists() && (local.isDirectory() || !local.canRead() || !local.canWrite()))
            return null;

        String key = Integer.toHexString(local.hashCode());
        String[] metadata = db.getProperty(key, "0:0:").split(":", 3);

        long size = 0;
        long expire = 0;
        String etag = "";

        if (metadata.length != 3)
            System.err.println("Bad metadata in key: " + key);
        else
        {
            try
            {
                size = Long.parseLong(metadata[0]);
                expire = Long.parseLong(metadata[1]);
                etag = metadata[2];
            }
            catch (NumberFormatException e)
            {
                size = 0;
                expire = 0;
                etag = "";
                System.err.println("Bad metadata in key: " + key);
            }
        }

        int tries = 0;
        boolean metadataChanged = false;

        System.out.println("reading remote file: " + remote);

        URLConnection conn = null;
        while (tries++ < maxTries)
        {
            try
            {
                boolean expired = local.exists() && size == local.length() ? System.currentTimeMillis() > expire : true;

                conn = remote.openConnection(proxy);
                conn.setConnectTimeout(30000);
                conn.setReadTimeout(10000);
                if (!expired && !etag.isEmpty())
                    conn.setRequestProperty("If-None-Match", etag);
                conn.connect();

                if (conn instanceof HttpURLConnection)
                {
                    HttpURLConnection c = (HttpURLConnection) conn;
                    int code = c.getResponseCode();
                    if (tries > 1)
                        System.out.println("remote response (" + tries + "/" + maxTries + "): " + code);
                    else
                        System.out.println("remote response: " + code);
                    switch (code / 100)
                    {
                        case 4:
                            return null;
                        case 2:
                            FileOutputStream fos = null;
                            try
                            {
                                fos = new FileOutputStream(local);
                                fos.getChannel().transferFrom(Channels.newChannel(conn.getInputStream()), 0, Long.MAX_VALUE);
                            }
                            finally
                            {
                                if (fos != null)
                                    fos.close();
                            }
                            break;
                        default:
                            if (code != 304 && !handleErrorCode.test(code))
                                return null;
                            break;
                    }
                }
                else
                {
                    FileOutputStream fos = null;
                    try
                    {
                        fos = new FileOutputStream(local);
                        fos.getChannel().transferFrom(Channels.newChannel(conn.getInputStream()), 0, Long.MAX_VALUE);
                    }
                    finally
                    {
                        if (fos != null)
                            fos.close();
                    }
                }

                Map<String, String> cacheControl = parseField(conn.getHeaderField("Cache-Control"));
                if (!cacheControl.containsKey("no-cache"))
                {
                    etag = conn.getHeaderField("Etag");
                    int age = 0;
                    try
                    {
                        if (cacheControl.containsKey("max-age"))
                            age = Integer.parseInt(cacheControl.get("max-age"));
                    }
                    catch (NumberFormatException e)
                    {
                        age = 0;
                    }
                    expire = Math.max(age > 0 ? (System.currentTimeMillis() + (age * 1000)) : conn.getExpiration(), System.currentTimeMillis() + (CacheMinTTL * 1000));
                    size = local.length();
                    db.setProperty(key, size + ":" + expire + ":" + etag);
                    metadataChanged = true;
                }
                else
                {
                    db.remove(key);
                    metadataChanged = true;
                }

                if (local.exists() && !local.isDirectory() && local.canRead())
                    return new FileInputStream(local);
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            finally
            {
                if (metadataChanged)
                    saveDB();
            }
        }

        return null;
    }

    static void saveDB()
    {
        System.out.println("saving database");
        try
        {
            db.store(new FileOutputStream(db_file), null);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        System.out.println("saved database");
    }

    private static final File db_file = new File("MyDnsTool.db");
    private static final Properties db = new Properties();
    private static final int CacheMinTTL = 600;

}

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class Main {
    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/healthz", ex -> respond(ex, 200, "ok\n"));
        server.createContext("/notes", ex -> respond(ex, 200,
            "[{\"id\":1,\"text\":\"buy milk\"},"
          + "{\"id\":2,\"text\":\"finish INF 345 week 3\"}]\n"));
        server.createContext("/", ex -> respond(ex, 200, "Hello from INF 345!\n"));

        server.start();
        System.out.println("Listening on port " + port);
    }

    private static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes("UTF-8");
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        OutputStream out = ex.getResponseBody();
        out.write(bytes);
        out.close();
        ex.close();
    }
}
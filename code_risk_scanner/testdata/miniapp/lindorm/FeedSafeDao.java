package lindorm;

import java.util.ArrayList;
import java.util.List;

public class FeedSafeDao {
    public void put(String id, String url) {
        String rowKey = md5(id).substring(0, 4) + System.currentTimeMillis() + id;
        Put put = new Put(Bytes.toBytes(rowKey));
        put.addColumn(CF, Q, url.getBytes());
        table.put(put);
    }

    public ResultScanner scan(byte[] start, byte[] stop) {
        Scan scan = new Scan().withStartRow(start).withStopRow(stop);
        scan.setLimit(100);
        return table.getScanner(scan);
    }

    public void batch(List<String> ids) {
        List<Put> puts = new ArrayList<Put>();
        for (String id : ids) {
            puts.add(new Put(Bytes.toBytes(id)));
            if (puts.size() >= 100) {
                table.put(puts);
                puts.clear();
            }
        }
        if (!puts.isEmpty()) {
            table.put(puts);
        }
    }
}

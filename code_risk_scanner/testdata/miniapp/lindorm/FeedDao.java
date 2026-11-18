package lindorm;

import java.util.ArrayList;
import java.util.List;

public class FeedDao {
    public void put(String id, List<String> rows) {
        String rowKey = System.currentTimeMillis() + "_" + id;
        Put put = new Put(Bytes.toBytes(rowKey));
        put.addColumn(CF, Q, JSON.toJSONString(rows).getBytes());
        table.put(put);
    }

    public ResultScanner scanAll() {
        Scan scan = new Scan();
        scan.setFilter(new ValueFilter(CompareOp.EQUAL, new SubstringComparator("vip")));
        return table.getScanner(scan);
    }

    public void batch(List<String> ids) {
        List<Put> puts = new ArrayList<Put>();
        for (String id : ids) {
            puts.add(new Put(Bytes.toBytes(id)));
        }
        table.put(puts);
    }
}

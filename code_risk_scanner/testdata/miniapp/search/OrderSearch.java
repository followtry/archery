package search;

public class OrderSearch {
    public void page(int page, int size) {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.from(page * size);
        sourceBuilder.size(size);
    }

    public void export() {
        for (int from = 0; ; from += 1000) {
            SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
            sourceBuilder.from(from);
            sourceBuilder.size(1000);
        }
    }

    public void fuzzy(String keyword) {
        QueryBuilders.wildcardQuery("name", "*" + keyword + "*");
    }

    public void scripted() {
        new Script("painless", "doc['price'].value * 2");
    }
}

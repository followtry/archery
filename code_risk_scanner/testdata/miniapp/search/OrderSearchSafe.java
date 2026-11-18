package search;

public class OrderSearchSafe {
    public void page(Object[] sortValues, int size) {
        SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();
        sourceBuilder.searchAfter(sortValues);
        sourceBuilder.size(size);
    }

    public void fuzzy(String keyword) {
        QueryBuilders.matchQuery("name", keyword);
    }
}

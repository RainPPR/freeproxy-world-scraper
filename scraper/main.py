import json

import yaml

from freeproxy_world_scraper import fetch_freeproxy_work_pagerandom


def main():
    with open("../config.yml", "r", encoding="utf-8") as f:
        config_data = yaml.safe_load(f)

    configs = config_data["freeproxy_list"]
    all_results = set()

    for key, value in configs.items():
        print(f"正在抓取配置: {key}")
        results = fetch_freeproxy_work_pagerandom(value, 200)
        all_results.update(results)

    output = [result.all for result in all_results]
    with open("../data/raw.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    print(f"共获取 {len(output)} 个代理节点，已保存至 data/raw.json")


if __name__ == "__main__":
    main()

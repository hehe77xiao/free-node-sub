"""根据节点名识别国家 / 地区，用于分组。"""

from __future__ import annotations

import re
from dataclasses import dataclass

_REGIONAL_INDICATOR_BASE = 0x1F1E6


@dataclass(frozen=True)
class Region:
    key: str
    flag: str
    label: str

    @property
    def group_name(self) -> str:
        return f"{self.flag} {self.label}"


# key -> (emoji, 中文名, 匹配词列表)
_REGION_PATTERNS: list[tuple[str, str, str, list[str]]] = [
    ("hk", "🇭🇰", "香港", ["香港", "hong kong", "hongkong", "hk"]),
    ("us", "🇺🇸", "美国", ["美国", "united states", "usa", "u.s", "america", "us"]),
    ("jp", "🇯🇵", "日本", ["日本", "japan", "tokyo", "jp"]),
    ("sg", "🇸🇬", "新加坡", ["新加坡", "singapore", "sg"]),
    ("kr", "🇰🇷", "韩国", ["韩国", "korea", "seoul", "kr"]),
    ("de", "🇩🇪", "德国", ["德国", "germany", "frankfurt", "de"]),
    ("gb", "🇬🇧", "英国", ["英国", "united kingdom", "london", "gbr", "uk"]),
    ("fr", "🇫🇷", "法国", ["法国", "france", "paris", "fr"]),
    ("nl", "🇳🇱", "荷兰", ["荷兰", "netherlands", "amsterdam", "nl"]),
    ("ca", "🇨🇦", "加拿大", ["加拿大", "canada", "toronto", "ca"]),
    ("au", "🇦🇺", "澳大利亚", ["澳大利亚", "australia", "sydney", "au"]),
    ("ru", "🇷🇺", "俄罗斯", ["俄罗斯", "russia", "moscow", "ru"]),
    ("tw", "🇹🇼", "台湾", ["台湾", "taiwan", "taipei", "tw"]),
    ("vn", "🇻🇳", "越南", ["越南", "vietnam", "hanoi", "vn"]),
    ("th", "🇹🇭", "泰国", ["泰国", "thailand", "bangkok", "th"]),
    ("tr", "🇹🇷", "土耳其", ["土耳其", "turkey", "istanbul", "tr"]),
    ("ae", "🇦🇪", "阿联酋", ["阿联酋", "emirates", "dubai", "ae"]),
    ("in", "🇮🇳", "印度", ["印度", "india", "mumbai", "in"]),
    ("br", "🇧🇷", "巴西", ["巴西", "brazil", "sao paulo", "br"]),
    ("es", "🇪🇸", "西班牙", ["西班牙", "spain", "madrid", "es"]),
    ("it", "🇮🇹", "意大利", ["意大利", "italy", "rome", "it"]),
    ("se", "🇸🇪", "瑞典", ["瑞典", "sweden", "stockholm", "se"]),
    ("pl", "🇵🇱", "波兰", ["波兰", "poland", "warsaw", "pl"]),
    ("pt", "🇵🇹", "葡萄牙", ["葡萄牙", "portugal", "pt"]),
    ("at", "🇦🇹", "奥地利", ["奥地利", "austria", "vienna", "at"]),
    ("ch", "🇨🇭", "瑞士", ["瑞士", "switzerland", "zurich", "ch"]),
    ("no", "🇳🇴", "挪威", ["挪威", "norway", "oslo", "no"]),
    ("fi", "🇫🇮", "芬兰", ["芬兰", "finland", "helsinki", "fi"]),
    ("dk", "🇩🇰", "丹麦", ["丹麦", "denmark", "copenhagen", "dk"]),
    ("ie", "🇮🇪", "爱尔兰", ["爱尔兰", "ireland", "dublin", "ie"]),
    ("nz", "🇳🇿", "新西兰", ["新西兰", "new zealand", "nz"]),
    ("my", "🇲🇾", "马来西亚", ["马来西亚", "malaysia", "kualalumpur", "kuala lumpur", "my"]),
    ("id", "🇮🇩", "印尼", ["印尼", "indonesia", "jakarta", "id"]),
    ("ph", "🇵🇭", "菲律宾", ["菲律宾", "philippines", "manila", "ph"]),
    ("kz", "🇰🇿", "哈萨克斯坦", ["哈萨克", "kazakhstan", "kz"]),
    ("ua", "🇺🇦", "乌克兰", ["乌克兰", "ukraine", "kyiv", "ua"]),
    ("ro", "🇷🇴", "罗马尼亚", ["罗马尼亚", "romania", "ro"]),
    ("hu", "🇭🇺", "匈牙利", ["匈牙利", "hungary", "budapest", "hu"]),
    ("gr", "🇬🇷", "希腊", ["希腊", "greece", "athens", "gr"]),
    ("mx", "🇲🇽", "墨西哥", ["墨西哥", "mexico", "mx"]),
    ("ar", "🇦🇷", "阿根廷", ["阿根廷", "argentina", "ar"]),
    ("za", "🇿🇦", "南非", ["南非", "south africa", "za"]),
    ("il", "🇮🇱", "以色列", ["以色列", "israel", "il"]),
    ("sa", "🇸🇦", "沙特", ["沙特", "saudi", "sa"]),
]

OTHER = Region(key="other", flag="🌍", label="其他")
UNKNOWN = Region(key="unknown", flag="🏳️", label="未标注")


def _extract_flag_codes(name: str) -> list[str]:
    """把节点名中的国旗 emoji（成对区域指示符）还原为两位国家码。"""
    codes: list[str] = []
    chars = list(name)
    index = 0
    while index < len(chars) - 1:
        first, second = chars[index], chars[index + 1]
        if (
            _REGIONAL_INDICATOR_BASE <= ord(first) <= 0x1F1FF
            and _REGIONAL_INDICATOR_BASE <= ord(second) <= 0x1F1FF
        ):
            code = chr(ord(first) - _REGIONAL_INDICATOR_BASE + ord("A")) + chr(
                ord(second) - _REGIONAL_INDICATOR_BASE + ord("A")
            )
            codes.append(code.lower())
            index += 2
        else:
            index += 1
    return codes


def _compile_patterns() -> list[tuple[Region, list[re.Pattern[str]]]]:
    compiled: list[tuple[Region, list[re.Pattern[str]]]] = []
    for key, flag, label, words in _REGION_PATTERNS:
        region = Region(key=key, flag=flag, label=label)
        patterns: list[re.Pattern[str]] = []
        for word in words:
            if re.fullmatch(r"[a-z. ]+", word):
                # 英文词加词边界，避免 "us" 命中 "status"
                patterns.append(re.compile(rf"(?<![a-z]){re.escape(word)}(?![a-z])"))
            else:
                patterns.append(re.compile(re.escape(word)))
        compiled.append((region, patterns))
    return compiled


_COMPILED = _compile_patterns()


def detect_region(name: str) -> Region:
    haystack = name.lower()
    flag_codes = _extract_flag_codes(name)
    if flag_codes:
        haystack = f"{haystack} {' '.join(flag_codes)}"
    for region, patterns in _COMPILED:
        for pattern in patterns:
            if pattern.search(haystack):
                return region
    if flag_codes:
        return OTHER
    return UNKNOWN

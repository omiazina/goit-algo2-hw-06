import json
import time
import math
import mmh3


class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2  # Поріг для малих значень

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z
        
        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)
        
        return E


def load_ips_from_log(file_path):
    ips = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                obj = json.loads(line.strip())
                ip = obj.get("remote_addr", None)
                if ip:
                    ips.append(ip)
            except json.JSONDecodeError:
                continue
    return ips


def exact_count(ips):
    return len(set(ips))


def hll_count(ips):
    hll = HyperLogLog(p=14)
    for ip in ips:
        hll.add(ip)
    return hll.count()


def compare_methods(ips):
    # Точний
    start = time.time()
    exact = exact_count(ips)
    exact_time = time.time() - start

    # HyperLogLog
    start = time.time()
    approx = hll_count(ips)
    hll_time = time.time() - start

    return exact, exact_time, approx, hll_time


# -------------------------------
#              MAIN
# -------------------------------
if __name__ == "__main__":
    log_file = "lms-stage-access.log"

    print("Завантаження логів...")
    ips = load_ips_from_log(log_file)

    print(f"Кількість прочитаних записів: {len(ips)}")

    exact, exact_time, approx, hll_time = compare_methods(ips)

    print("\nРезультати порівняння:")
    print(f"{'Метод':25} {'Унікальні елементи':20} {'Час (сек.)'}")
    print(f"{'-'*60}")
    print(f"{'Точний підрахунок':25} {exact:<20} {exact_time:.4f}")
    print(f"{'HyperLogLog':25} {approx:<20.0f} {hll_time:.4f}")

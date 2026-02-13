#!/usr/bin/env python3

import sys
import subprocess
import platform
import argparse
import time
import os
import random
import ipaddress
from typing import Dict, List, Optional, Tuple

class IPChanger:
    def __init__(self, os_type=None):
        self.os_type = os_type or platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        
    def detect_linux_distro(self) -> str:
        """Определяет дистрибутив Linux"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        distro = line.split('=')[1].strip().strip('"')
                        return distro.lower()
        except:
            pass
        return 'unknown'
    
    def run_command(self, cmd: List[str]) -> Tuple[bool, str]:
        """Выполняет команду и возвращает результат"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)
    
    def is_admin(self) -> bool:
        """Проверяет, запущен ли скрипт с правами администратора"""
        if self.os_type == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def get_network_interfaces(self) -> List[str]:
        """Получает список сетевых интерфейсов"""
        interfaces = []
        
        if self.os_type == 'Windows':
            # Первый метод через netsh
            success, output = self.run_command(['netsh', 'interface', 'show', 'interface'])
            if success:
                lines = output.split('\n')
                for line in lines:
                    if 'Enabled' in line or 'Connected' in line:
                        parts = line.strip().split()
                        if parts:
                            # Имя интерфейса обычно в конце строки
                            interface_name = parts[-1]
                            if interface_name and len(interface_name) > 1:
                                interfaces.append(interface_name)
            
            # Второй метод через ipconfig
            if not interfaces:
                success, output = self.run_command(['ipconfig'])
                if success:
                    for line in output.split('\n'):
                        if 'adapter' in line.lower() and ':' in line:
                            iface = line.split(':')[0].strip()
                            if iface and iface not in interfaces:
                                interfaces.append(iface)
        else:
            # Linux
            success, output = self.run_command(['ip', '-o', 'link', 'show'])
            if success:
                for line in output.split('\n'):
                    if 'LOOPBACK' not in line and 'link/' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            iface = parts[1].strip()
                            if iface and '@' not in iface:
                                interfaces.append(iface)
        
        return list(dict.fromkeys(interfaces))  # Убираем дубликаты с сохранением порядка
    
    def get_current_ip(self, interface: str) -> Dict[str, str]:
        """Получает текущие сетевые настройки интерфейса"""
        result = {}
        
        if self.os_type == 'Windows':
            # Получаем конфигурацию для конкретного интерфейса
            success, output = self.run_command(['netsh', 'interface', 'ip', 'show', 'config', f'name={interface}'])
            if success:
                for line in output.split('\n'):
                    line = line.strip()
                    if 'IP Address:' in line and 'IPv4' in line:
                        result['ip'] = line.split(':')[1].strip()
                    elif 'Subnet Mask:' in line:
                        result['mask'] = line.split(':')[1].strip()
                    elif 'Default Gateway:' in line and 'None' not in line:
                        result['gateway'] = line.split(':')[1].strip()
        else:
            # Linux
            success, output = self.run_command(['ip', '-o', 'addr', 'show', interface])
            if success:
                for line in output.split('\n'):
                    if 'inet ' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_with_mask = parts[3]
                            if '/' in ip_with_mask:
                                ip_parts = ip_with_mask.split('/')
                                result['ip'] = ip_parts[0]
                                if len(ip_parts) > 1:
                                    result['mask'] = self.cidr_to_netmask(int(ip_parts[1]))
            
            # Получаем шлюз
            success, output = self.run_command(['ip', 'route', 'show', 'default'])
            if success and output:
                for line in output.split('\n'):
                    if interface in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            result['gateway'] = parts[2]
                            break
        
        return result
    
    def cidr_to_netmask(self, cidr: int) -> str:
        """Конвертирует CIDR в маску подсети"""
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
    
    def netmask_to_cidr(self, netmask: str) -> int:
        """Конвертирует маску подсети в CIDR"""
        try:
            return sum(bin(int(x)).count('1') for x in netmask.split('.'))
        except:
            return 24  # Значение по умолчанию
    
    def generate_random_ip(self, gateway: str, mask: str) -> str:
        """Генерирует случайный IP в той же подсети"""
        try:
            # Получаем сеть из шлюза и маски
            network = ipaddress.IPv4Network(f"{gateway}/{mask}", strict=False)
            
            # Получаем все возможные хосты в сети
            hosts = list(network.hosts())
            
            if hosts:
                # Выбираем случайный IP
                random_ip = str(random.choice(hosts))
                return random_ip
            else:
                # Если сеть слишком маленькая, используем предсказуемый IP
                network_parts = gateway.split('.')[:3]
                random_last = random.randint(2, 254)
                return f"{'.'.join(network_parts)}.{random_last}"
                
        except Exception as e:
            print(f"Ошибка генерации IP: {e}")
            # Резервный метод
            network_parts = gateway.split('.')[:3]
            random_last = random.randint(2, 254)
            return f"{'.'.join(network_parts)}.{random_last}"
    
    def validate_ip_in_network(self, ip: str, gateway: str, mask: str) -> bool:
        """Проверяет, находится ли IP в той же подсети, что и шлюз"""
        try:
            ip_net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            gateway_net = ipaddress.IPv4Network(f"{gateway}/{mask}", strict=False)
            return ip_net.network_address == gateway_net.network_address
        except:
            return False
    
    def change_ip_linux(self, interface: str, ip: str, mask: str, gateway: Optional[str] = None) -> bool:
        """Меняет IP на Linux"""
        print(f"\nКонфигурация:")
        print(f"  Интерфейс: {interface}")
        print(f"  IP-адрес: {ip}")
        print(f"  Маска: {mask}")
        if gateway:
            print(f"  Шлюз: {gateway}")
        
        try:
            # Удаляем старые адреса
            print("  1. Очистка старых адресов...")
            self.run_command(['ip', 'addr', 'flush', 'dev', interface])
            
            # Устанавливаем новый IP
            print("  2. Установка нового IP...")
            cidr = self.netmask_to_cidr(mask)
            success, output = self.run_command(['ip', 'addr', 'add', f"{ip}/{cidr}", 'dev', interface])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            # Включаем интерфейс
            print("  3. Активация интерфейса...")
            success, output = self.run_command(['ip', 'link', 'set', interface, 'up'])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            # Устанавливаем шлюз, если указан
            if gateway:
                print("  4. Настройка шлюза...")
                # Удаляем старый маршрут по умолчанию
                self.run_command(['ip', 'route', 'del', 'default'])
                # Добавляем новый маршрут
                success, output = self.run_command(['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface])
                
                if not success:
                    print(f"  Ошибка установки шлюза: {output}")
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def change_ip_windows(self, interface: str, ip: str, mask: str, gateway: Optional[str] = None) -> bool:
        """Меняет IP на Windows"""
        print(f"\nКонфигурация:")
        print(f"  Интерфейс: {interface}")
        print(f"  IP-адрес: {ip}")
        print(f"  Маска: {mask}")
        if gateway:
            print(f"  Шлюз: {gateway}")
        
        try:
            # Устанавливаем статический IP
            print("  1. Установка статического IP...")
            if gateway:
                cmd_set_ip = ['netsh', 'interface', 'ip', 'set', 'address', 
                            f'name={interface}', 'static', ip, mask, gateway, '1']
            else:
                cmd_set_ip = ['netsh', 'interface', 'ip', 'set', 'address', 
                            f'name={interface}', 'static', ip, mask]
            
            success, output = self.run_command(cmd_set_ip)
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def set_dhcp_linux(self, interface: str) -> bool:
        """Устанавливает DHCP на Linux"""
        print(f"\nВключение DHCP на интерфейсе {interface}...")
        
        try:
            print("  1. Освобождение текущего адреса...")
            self.run_command(['dhclient', '-r', interface])
            time.sleep(1)
            
            print("  2. Запрос нового адреса...")
            success, output = self.run_command(['dhclient', interface])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def set_dhcp_windows(self, interface: str) -> bool:
        """Устанавливает DHCP на Windows"""
        print(f"\nВключение DHCP на интерфейсе {interface}...")
        
        try:
            cmd = ['netsh', 'interface', 'ip', 'set', 'address', 
                  f'name={interface}', 'dhcp']
            
            success, output = self.run_command(cmd)
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False

def select_os() -> str:
    """Интерактивный выбор ОС"""
    print("\n" + "="*50)
    print("ВЫБОР ОПЕРАЦИОННОЙ СИСТЕМЫ")
    print("="*50)
    
    os_options = {
        '1': 'Windows',
        '2': 'Linux',
        '3': 'Автоопределение'
    }
    
    for key, value in os_options.items():
        print(f"  {key}. {value}")
    
    while True:
        choice = input("\nВыберите ОС (1-3): ").strip()
        if choice in os_options:
            if choice == '1':
                return 'Windows'
            elif choice == '2':
                return 'Linux'
            else:
                return platform.system()
        else:
            print("Неверный выбор! Попробуйте снова.")

def select_interface(ip_changer: IPChanger) -> str:
    """Интерактивный выбор интерфейса"""
    interfaces = ip_changer.get_network_interfaces()
    
    if not interfaces:
        print("Не найдено сетевых интерфейсов!")
        return None
    
    print("\n" + "="*50)
    print("ДОСТУПНЫЕ СЕТЕВЫЕ ИНТЕРФЕЙСЫ")
    print("="*50)
    
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    
    print(f"  {len(interfaces) + 1}. Ввести вручную")
    
    while True:
        choice = input(f"\nВыберите интерфейс (1-{len(interfaces) + 1}): ").strip()
        
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
            elif idx == len(interfaces) + 1:
                manual_iface = input("Введите имя интерфейса: ").strip()
                if manual_iface:
                    return manual_iface
        print("Неверный выбор! Попробуйте снова.")

def get_ip_mode(ip_changer: IPChanger, current_config: Dict[str, str]) -> tuple:
    """Выбор режима получения IP"""
    print("\n" + "="*50)
    print("РЕЖИМ НАСТРОЙКИ IP")
    print("="*50)
    
    modes = {
        '1': 'Ручной ввод',
        '2': 'Автоматический (случайный IP в той же подсети)',
        '3': 'DHCP (автоматическое получение от роутера)'
    }
    
    for key, value in modes.items():
        print(f"  {key}. {value}")
    
    while True:
        choice = input("\nВыберите режим (1-3): ").strip()
        
        if choice == '1':  # Ручной ввод
            print("\n--- РУЧНОЙ ВВОД IP ---")
            
            # Показываем текущую сеть для справки
            if 'gateway' in current_config and 'mask' in current_config:
                print(f"Текущая сеть: {current_config['gateway']}/{current_config['mask']}")
                print(f"Рекомендуемый диапазон: {current_config['gateway'].rsplit('.', 1)[0]}.X (X=2-254)")
            
            while True:
                ip = input("Введите IP-адрес (например, 192.168.1.100): ").strip()
                try:
                    ipaddress.IPv4Address(ip)  # Проверка валидности
                    break
                except:
                    print("Неверный IP-адрес! Попробуйте снова.")
            
            while True:
                default_mask = current_config.get('mask', '255.255.255.0')
                mask = input(f"Введите маску подсети [по умолчанию {default_mask}]: ").strip()
                if not mask:
                    mask = default_mask
                
                try:
                    # Проверяем валидность маски
                    ipaddress.IPv4Network(f"192.168.1.1/{mask}", strict=False)
                    break
                except:
                    print("Неверная маска подсети! Попробуйте снова.")
            
            while True:
                default_gateway = current_config.get('gateway', '')
                gateway = input(f"Введите шлюз [по умолчанию {default_gateway}]: ").strip()
                if not gateway and default_gateway:
                    gateway = default_gateway
                elif not gateway:
                    gateway = None
                    break
                
                try:
                    ipaddress.IPv4Address(gateway)
                    break
                except:
                    print("Неверный адрес шлюза! Попробуйте снова.")
            
            return 'static', ip, mask, gateway
            
        elif choice == '2':  # Автоматический режим
            if 'gateway' not in current_config or 'mask' not in current_config:
                print("Не удалось определить текущий шлюз или маску. Используйте ручной режим.")
                continue
            
            gateway = current_config.get('gateway')
            mask = current_config.get('mask')
            
            if not gateway:
                print("Не удалось определить шлюз. Используйте ручной режим.")
                continue
            
            # Генерируем случайный IP
            random_ip = ip_changer.generate_random_ip(gateway, mask)
            print(f"\n--- АВТОМАТИЧЕСКИЙ РЕЖИМ ---")
            print(f"Текущая сеть: {gateway}/{mask}")
            print(f"Сгенерирован случайный IP: {random_ip}")
            
            confirm = input("Использовать этот IP? (y/n): ").strip().lower()
            if confirm == 'y':
                return 'static', random_ip, mask, gateway
            else:
                print("Возврат к выбору режима...")
                continue
                
        elif choice == '3':  # DHCP
            return 'dhcp', None, None, None
            
        else:
            print("Неверный выбор! Попробуйте снова.")

def main():
    parser = argparse.ArgumentParser(
        description='Универсальный скрипт для изменения IP-адреса',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Аргументы командной строки для автоматизации
    parser.add_argument('--os', choices=['windows', 'linux', 'auto'], 
                       help='Операционная система (windows/linux/auto)')
    parser.add_argument('--interface', '-i', help='Сетевой интерфейс')
    parser.add_argument('--ip', help='IP-адрес (для ручного режима)')
    parser.add_argument('--mask', help='Маска подсети')
    parser.add_argument('--gateway', '-g', help='Шлюз по умолчанию')
    parser.add_argument('--dhcp', action='store_true', help='Включить DHCP')
    parser.add_argument('--random', '-r', action='store_true', 
                       help='Использовать случайный IP в текущей подсети')
    parser.add_argument('--list', '-l', action='store_true', 
                       help='Показать список интерфейсов и выйти')
    
    args = parser.parse_args()
    
    # Определяем ОС
    if args.os:
        if args.os == 'windows':
            os_type = 'Windows'
        elif args.os == 'linux':
            os_type = 'Linux'
        else:
            os_type = None
    else:
        # Интерактивный выбор, если не указан аргумент
        os_type = None
    
    # Создаем объект IPChanger
    if os_type:
        ip_changer = IPChanger(os_type)
        print(f"Используется ОС: {os_type}")
    else:
        os_type = select_os()
        ip_changer = IPChanger(os_type)
    
    # Проверка прав администратора
    if not ip_changer.is_admin():
        print("\n" + "~"*50)
        print("ОШИБКА: Требуются права администратора!")
        print("~"*50)
        
        if ip_changer.os_type == 'Windows':
            print("\nДля Windows:")
            print("  1. Нажмите Win+X")
            print("  2. Выберите 'Windows PowerShell (Admin)' или 'Командная строка (Admin)'")
            print("  3. Запустите скрипт: python script.py")
        else:
            print("\nДля Linux:")
            print("  sudo python3 ip.py")
        
        sys.exit(1)
    
    # Показать список интерфейсов и выйти
    if args.list:
        print("\n" + "="*50)
        print("СЕТЕВЫЕ ИНТЕРФЕЙСЫ")
        print("="*50)
        
        interfaces = ip_changer.get_network_interfaces()
        if interfaces:
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
                # Показываем текущие настройки для каждого интерфейса
                config = ip_changer.get_current_ip(iface)
                if config.get('ip'):
                    print(f"     IP: {config.get('ip', 'Нет')}")
                    print(f"     Маска: {config.get('mask', 'Нет')}")
                    print(f"     Шлюз: {config.get('gateway', 'Нет')}")
                    print()
        else:
            print("  Интерфейсы не найдены!")
        return
    
    # Определяем интерфейс
    if args.interface:
        interface = args.interface
        print(f"Используется интерфейс: {interface}")
    else:
        interface = select_interface(ip_changer)
        if not interface:
            print("Не выбран интерфейс!")
            return
    
    # Получаем текущие настройки
    print(f"\nПолучение текущих настроек для {interface}...")
    current_config = ip_changer.get_current_ip(interface)
    
    if current_config:
        print("\nТЕКУЩИЕ НАСТРОЙКИ:")
        for key, value in current_config.items():
            print(f"  {key}: {value}")
    else:
        print("Не удалось получить текущие настройки.")
        current_config = {}
    
    # Определяем режим работы
    if args.dhcp:
        mode = 'dhcp'
        ip = mask = gateway = None
    elif args.random:
        mode = 'static'
        if 'gateway' in current_config and 'mask' in current_config:
            gateway = current_config['gateway']
            mask = current_config.get('mask', '255.255.255.0')
            ip = ip_changer.generate_random_ip(gateway, mask)
            print(f"\nСгенерирован случайный IP: {ip}")
        else:
            print("Не удалось определить шлюз для генерации случайного IP!")
            return
    elif args.ip:
        mode = 'static'
        ip = args.ip
        mask = args.mask or current_config.get('mask', '255.255.255.0')
        gateway = args.gateway or current_config.get('gateway')
    else:
        # Интерактивный режим
        mode, ip, mask, gateway = get_ip_mode(ip_changer, current_config)
    
    # Выполняем изменение настроек
    print("\n" + "="*50)
    print("ВЫПОЛНЕНИЕ ИЗМЕНЕНИЙ")
    print("="*50)
    
    try:
        if mode == 'dhcp':
            # Включаем DHCP
            if ip_changer.os_type == 'Windows':
                success = ip_changer.set_dhcp_windows(interface)
            else:
                success = ip_changer.set_dhcp_linux(interface)
            
            if success:
                print("\n✓ DHCP успешно включен!")
            else:
                print("\n✗ Ошибка включения DHCP!")
                
        elif mode == 'static':
            # Проверяем, находится ли IP в правильной подсети
            if gateway and mask and ip:
                if not ip_changer.validate_ip_in_network(ip, gateway, mask):
                    print("\n⚠ ВНИМАНИЕ: IP не находится в той же подсети, что и шлюз!")
                    print(f"  IP: {ip}")
                    print(f"  Сеть шлюза: {gateway}/{mask}")
                    
                    response = input("Продолжить? (y/n): ").strip().lower()
                    if response != 'y':
                        print("Операция отменена.")
                        return
            
            # Устанавливаем статический IP
            if ip_changer.os_type == 'Windows':
                success = ip_changer.change_ip_windows(interface, ip, mask, gateway)
            else:
                success = ip_changer.change_ip_linux(interface, ip, mask, gateway)
            
            if success:
                print("\n✓ Настройки успешно применены!")
            else:
                print("\n✗ Ошибка применения настроек!")
        
        # Показываем новые настройки
        if mode in ['dhcp', 'static']:
            print("\n" + "-"*30)
            print("ПРОВЕРКА НОВЫХ НАСТРОЕК")
            print("-"*30)
            time.sleep(3)  # Даем время для применения настроек
            
            new_config = ip_changer.get_current_ip(interface)
            if new_config:
                for key, value in new_config.items():
                    print(f"  {key}: {value}")
            else:
                print("  Не удалось получить новые настройки")
            
            # Тестируем подключение
            print("\n" + "-"*30)
            print("ТЕСТ ПОДКЛЮЧЕНИЯ")
            print("-"*30)
            
            test_target = gateway or '8.8.8.8' or '192.168.1.1'
            print(f"Тестируем ping до {test_target}...")
            
            if ip_changer.os_type == 'Windows':
                ping_cmd = ['ping', '-n', '2', '-w', '1000', test_target]
            else:
                ping_cmd = ['ping', '-c', '2', '-W', '1', test_target]
            
            ping_success, ping_output = ip_changer.run_command(ping_cmd)
            if ping_success:
                print("✓ Сетевое подключение работает")
            else:
                print("✗ Проблемы с сетевым подключением")
                
    except KeyboardInterrupt:
        print("\n\nОперация прервана пользователем")
    except Exception as e:
        print(f"\n✗ Критическая ошибка: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    # Проверка версии Python
    if sys.version_info < (3, 6):
        print("Требуется Python 3.6 или выше!")
        sys.exit(1)
    
    # Основная функция
    try:
        main()
    except Exception as e:
        print(f"\nНепредвиденная ошибка: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

import sys
import subprocess
import platform
import argparse
import time
import os
import random
import ipaddress
from typing import Dict, List, Optional, Tuple

class IPChanger:
    def __init__(self, os_type=None):
        self.os_type = os_type or platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        
    def detect_linux_distro(self) -> str:
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        distro = line.split('=')[1].strip().strip('"')
                        return distro.lower()
        except:
            pass
        return 'unknown'
    
    def run_command(self, cmd: List[str]) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)
    
    def is_admin(self) -> bool:
        if self.os_type == 'Windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def get_network_interfaces(self) -> List[str]:
        interfaces = []
        
        if self.os_type == 'Windows':
            success, output = self.run_command(['netsh', 'interface', 'show', 'interface'])
            if success:
                lines = output.split('\n')
                for line in lines:
                    if 'Enabled' in line or 'Connected' in line:
                        parts = line.strip().split()
                        if parts:
                            interface_name = parts[-1]
                            if interface_name and len(interface_name) > 1:
                                interfaces.append(interface_name)
            
            if not interfaces:
                success, output = self.run_command(['ipconfig'])
                if success:
                    for line in output.split('\n'):
                        if 'adapter' in line.lower() and ':' in line:
                            iface = line.split(':')[0].strip()
                            if iface and iface not in interfaces:
                                interfaces.append(iface)
        else:
            success, output = self.run_command(['ip', '-o', 'link', 'show'])
            if success:
                for line in output.split('\n'):
                    if 'LOOPBACK' not in line and 'link/' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            iface = parts[1].strip()
                            if iface and '@' not in iface:
                                interfaces.append(iface)
        
        return list(dict.fromkeys(interfaces))
    
    def get_current_ip(self, interface: str) -> Dict[str, str]:
        result = {}
        
        if self.os_type == 'Windows':
            success, output = self.run_command(['netsh', 'interface', 'ip', 'show', 'config', f'name={interface}'])
            if success:
                for line in output.split('\n'):
                    line = line.strip()
                    if 'IP Address:' in line and 'IPv4' in line:
                        result['ip'] = line.split(':')[1].strip()
                    elif 'Subnet Mask:' in line:
                        result['mask'] = line.split(':')[1].strip()
                    elif 'Default Gateway:' in line and 'None' not in line:
                        result['gateway'] = line.split(':')[1].strip()
        else:
            
            success, output = self.run_command(['ip', '-o', 'addr', 'show', interface])
            if success:
                for line in output.split('\n'):
                    if 'inet ' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_with_mask = parts[3]
                            if '/' in ip_with_mask:
                                ip_parts = ip_with_mask.split('/')
                                result['ip'] = ip_parts[0]
                                if len(ip_parts) > 1:
                                    result['mask'] = self.cidr_to_netmask(int(ip_parts[1]))
            
            
            success, output = self.run_command(['ip', 'route', 'show', 'default'])
            if success and output:
                for line in output.split('\n'):
                    if interface in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            result['gateway'] = parts[2]
                            break
        
        return result
    
    def cidr_to_netmask(self, cidr: int) -> str:
        mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
        return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
    
    def netmask_to_cidr(self, netmask: str) -> int:
        try:
            return sum(bin(int(x)).count('1') for x in netmask.split('.'))
        except:
            return 24
    
    def generate_random_ip(self, gateway: str, mask: str) -> str:
        try:
            
            network = ipaddress.IPv4Network(f"{gateway}/{mask}", strict=False)
            
        
            hosts = list(network.hosts())
            
            if hosts:
                random_ip = str(random.choice(hosts))
                return random_ip
            else:
                network_parts = gateway.split('.')[:3]
                random_last = random.randint(2, 254)
                return f"{'.'.join(network_parts)}.{random_last}"
                
        except Exception as e:
            print(f"Ошибка генерации IP: {e}")
            network_parts = gateway.split('.')[:3]
            random_last = random.randint(2, 254)
            return f"{'.'.join(network_parts)}.{random_last}"
    
    def validate_ip_in_network(self, ip: str, gateway: str, mask: str) -> bool:
        try:
            ip_net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            gateway_net = ipaddress.IPv4Network(f"{gateway}/{mask}", strict=False)
            return ip_net.network_address == gateway_net.network_address
        except:
            return False
    
    def change_ip_linux(self, interface: str, ip: str, mask: str, gateway: Optional[str] = None) -> bool:
        print(f"\nКонфигурация:")
        print(f"  Интерфейс: {interface}")
        print(f"  IP-адрес: {ip}")
        print(f"  Маска: {mask}")
        if gateway:
            print(f"  Шлюз: {gateway}")
        
        try:
            
            print("  1. Очистка старых адресов...")
            self.run_command(['ip', 'addr', 'flush', 'dev', interface])
            
            
            print("  2. Установка нового IP...")
            cidr = self.netmask_to_cidr(mask)
            success, output = self.run_command(['ip', 'addr', 'add', f"{ip}/{cidr}", 'dev', interface])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            
            print("  3. Активация интерфейса...")
            success, output = self.run_command(['ip', 'link', 'set', interface, 'up'])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
        
            if gateway:
                print("  4. Настройка шлюза...")
                self.run_command(['ip', 'route', 'del', 'default'])
                success, output = self.run_command(['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface])
                
                if not success:
                    print(f"  Ошибка установки шлюза: {output}")
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def change_ip_windows(self, interface: str, ip: str, mask: str, gateway: Optional[str] = None) -> bool:
        print(f"\nКонфигурация:")
        print(f"  Интерфейс: {interface}")
        print(f"  IP-адрес: {ip}")
        print(f"  Маска: {mask}")
        if gateway:
            print(f"  Шлюз: {gateway}")
        
        try:
            print("  1. Установка статического IP...")
            if gateway:
                cmd_set_ip = ['netsh', 'interface', 'ip', 'set', 'address', 
                            f'name={interface}', 'static', ip, mask, gateway, '1']
            else:
                cmd_set_ip = ['netsh', 'interface', 'ip', 'set', 'address', 
                            f'name={interface}', 'static', ip, mask]
            
            success, output = self.run_command(cmd_set_ip)
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def set_dhcp_linux(self, interface: str) -> bool:
        print(f"\nВключение DHCP на интерфейсе {interface}...")
        
        try:
            print("  1. Освобождение текущего адреса...")
            self.run_command(['dhclient', '-r', interface])
            time.sleep(1)
            
            print("  2. Запрос нового адреса...")
            success, output = self.run_command(['dhclient', interface])
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False
    
    def set_dhcp_windows(self, interface: str) -> bool:
        print(f"\nВключение DHCP на интерфейсе {interface}...")
        
        try:
            cmd = ['netsh', 'interface', 'ip', 'set', 'address', 
                  f'name={interface}', 'dhcp']
            
            success, output = self.run_command(cmd)
            
            if not success:
                print(f"  Ошибка: {output}")
                return False
            
            return True
            
        except Exception as e:
            print(f"  Ошибка: {str(e)}")
            return False

def select_os() -> str:
    print("\n" + "="*50)
    print("ВЫБОР ОПЕРАЦИОННОЙ СИСТЕМЫ")
    print("="*50)
    
    os_options = {
        '1': 'Windows',
        '2': 'Linux',
        '3': 'Автоопределение'
    }
    
    for key, value in os_options.items():
        print(f"  {key}. {value}")
    
    while True:
        choice = input("\nВыберите ОС (1-3): ").strip()
        if choice in os_options:
            if choice == '1':
                return 'Windows'
            elif choice == '2':
                return 'Linux'
            else:
                return platform.system()
        else:
            print("Неверный выбор! Попробуйте снова.")

def select_interface(ip_changer: IPChanger) -> str:
    interfaces = ip_changer.get_network_interfaces()
    
    if not interfaces:
        print("Не найдено сетевых интерфейсов!")
        return None
    
    print("\n" + "="*50)
    print("ДОСТУПНЫЕ СЕТЕВЫЕ ИНТЕРФЕЙСЫ")
    print("="*50)
    
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    
    print(f"  {len(interfaces) + 1}. Ввести вручную")
    
    while True:
        choice = input(f"\nВыберите интерфейс (1-{len(interfaces) + 1}): ").strip()
        
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
            elif idx == len(interfaces) + 1:
                manual_iface = input("Введите имя интерфейса: ").strip()
                if manual_iface:
                    return manual_iface
        print("Неверный выбор! Попробуйте снова.")

def get_ip_mode(ip_changer: IPChanger, current_config: Dict[str, str]) -> tuple:
    print("\n" + "="*50)
    print("РЕЖИМ НАСТРОЙКИ IP")
    print("="*50)
    
    modes = {
        '1': 'Ручной ввод',
        '2': 'Автоматический (случайный IP в той же подсети)',
        '3': 'DHCP (автоматическое получение от роутера)'
    }
    
    for key, value in modes.items():
        print(f"  {key}. {value}")
    
    while True:
        choice = input("\nВыберите режим (1-3): ").strip()
        
        if choice == '1':  
            print("\n--- РУЧНОЙ ВВОД IP ---")
            
            
            if 'gateway' in current_config and 'mask' in current_config:
                print(f"Текущая сеть: {current_config['gateway']}/{current_config['mask']}")
                print(f"Рекомендуемый диапазон: {current_config['gateway'].rsplit('.', 1)[0]}.X (X=2-254)")
            
            while True:
                ip = input("Введите IP-адрес (например, 192.168.1.100): ").strip()
                try:
                    ipaddress.IPv4Address(ip)  
                    break
                except:
                    print("Неверный IP-адрес! Попробуйте снова.")
            
            while True:
                default_mask = current_config.get('mask', '255.255.255.0')
                mask = input(f"Введите маску подсети [по умолчанию {default_mask}]: ").strip()
                if not mask:
                    mask = default_mask
                
                try:
                    ipaddress.IPv4Network(f"192.168.1.1/{mask}", strict=False)
                    break
                except:
                    print("Неверная маска подсети! Попробуйте снова.")
            
            while True:
                default_gateway = current_config.get('gateway', '')
                gateway = input(f"Введите шлюз [по умолчанию {default_gateway}]: ").strip()
                if not gateway and default_gateway:
                    gateway = default_gateway
                elif not gateway:
                    gateway = None
                    break
                
                try:
                    ipaddress.IPv4Address(gateway)
                    break
                except:
                    print("Неверный адрес шлюза! Попробуйте снова.")
            
            return 'static', ip, mask, gateway
            
        elif choice == '2':  
            if 'gateway' not in current_config or 'mask' not in current_config:
                print("Не удалось определить текущий шлюз или маску. Используйте ручной режим.")
                continue
            
            gateway = current_config.get('gateway')
            mask = current_config.get('mask')
            
            if not gateway:
                print("Не удалось определить шлюз. Используйте ручной режим.")
                continue
            
            
            random_ip = ip_changer.generate_random_ip(gateway, mask)
            print(f"\n--- АВТОМАТИЧЕСКИЙ РЕЖИМ ---")
            print(f"Текущая сеть: {gateway}/{mask}")
            print(f"Сгенерирован случайный IP: {random_ip}")
            
            confirm = input("Использовать этот IP? (y/n): ").strip().lower()
            if confirm == 'y':
                return 'static', random_ip, mask, gateway
            else:
                print("Возврат к выбору режима...")
                continue
                
        elif choice == '3':  
            return 'dhcp', None, None, None
            
        else:
            print("Неверный выбор! Попробуйте снова.")

def main():
    parser = argparse.ArgumentParser(
        description='Универсальный скрипт для изменения IP-адреса',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    
    parser.add_argument('--os', choices=['windows', 'linux', 'auto'], 
                       help='Операционная система (windows/linux/auto)')
    parser.add_argument('--interface', '-i', help='Сетевой интерфейс')
    parser.add_argument('--ip', help='IP-адрес (для ручного режима)')
    parser.add_argument('--mask', help='Маска подсети')
    parser.add_argument('--gateway', '-g', help='Шлюз по умолчанию')
    parser.add_argument('--dhcp', action='store_true', help='Включить DHCP')
    parser.add_argument('--random', '-r', action='store_true', 
                       help='Использовать случайный IP в текущей подсети')
    parser.add_argument('--list', '-l', action='store_true', 
                       help='Показать список интерфейсов и выйти')
    
    args = parser.parse_args()
    
    
    if args.os:
        if args.os == 'windows':
            os_type = 'Windows'
        elif args.os == 'linux':
            os_type = 'Linux'
        else:
            os_type = None
    else:
        
        os_type = None
    
    
    if os_type:
        ip_changer = IPChanger(os_type)
        print(f"Используется ОС: {os_type}")
    else:
        os_type = select_os()
        ip_changer = IPChanger(os_type)
    
    
    if not ip_changer.is_admin():
        print("\n" + "~"*50)
        print("ОШИБКА: Требуются права администратора!")
        print("~"*50)
        
        if ip_changer.os_type == 'Windows':
            print("\nДля Windows:")
            print("  1. Нажмите Win+X")
            print("  2. Выберите 'Windows PowerShell (Admin)' или 'Командная строка (Admin)'")
            print("  3. Запустите скрипт: python script.py")
        else:
            print("\nДля Linux:")
            print("  sudo python3 ip.py")
        
        sys.exit(1)
    

    if args.list:
        print("\n" + "="*50)
        print("СЕТЕВЫЕ ИНТЕРФЕЙСЫ")
        print("="*50)
        
        interfaces = ip_changer.get_network_interfaces()
        if interfaces:
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
        
                config = ip_changer.get_current_ip(iface)
                if config.get('ip'):
                    print(f"     IP: {config.get('ip', 'Нет')}")
                    print(f"     Маска: {config.get('mask', 'Нет')}")
                    print(f"     Шлюз: {config.get('gateway', 'Нет')}")
                    print()
        else:
            print("  Интерфейсы не найдены!")
        return
    
    
    if args.interface:
        interface = args.interface
        print(f"Используется интерфейс: {interface}")
    else:
        interface = select_interface(ip_changer)
        if not interface:
            print("Не выбран интерфейс!")
            return
    
    
    print(f"\nПолучение текущих настроек для {interface}...")
    current_config = ip_changer.get_current_ip(interface)
    
    if current_config:
        print("\nТЕКУЩИЕ НАСТРОЙКИ:")
        for key, value in current_config.items():
            print(f"  {key}: {value}")
    else:
        print("Не удалось получить текущие настройки.")
        current_config = {}
    
    
    if args.dhcp:
        mode = 'dhcp'
        ip = mask = gateway = None
    elif args.random:
        mode = 'static'
        if 'gateway' in current_config and 'mask' in current_config:
            gateway = current_config['gateway']
            mask = current_config.get('mask', '255.255.255.0')
            ip = ip_changer.generate_random_ip(gateway, mask)
            print(f"\nСгенерирован случайный IP: {ip}")
        else:
            print("Не удалось определить шлюз для генерации случайного IP!")
            return
    elif args.ip:
        mode = 'static'
        ip = args.ip
        mask = args.mask or current_config.get('mask', '255.255.255.0')
        gateway = args.gateway or current_config.get('gateway')
    else:
        
        mode, ip, mask, gateway = get_ip_mode(ip_changer, current_config)
    
    
    print("\n" + "="*50)
    print("ВЫПОЛНЕНИЕ ИЗМЕНЕНИЙ")
    print("="*50)
    
    try:
        if mode == 'dhcp':
            
            if ip_changer.os_type == 'Windows':
                success = ip_changer.set_dhcp_windows(interface)
            else:
                success = ip_changer.set_dhcp_linux(interface)
            
            if success:
                print("\n✓ DHCP успешно включен!")
            else:
                print("\n✗ Ошибка включения DHCP!")
                
        elif mode == 'static':
            
            if gateway and mask and ip:
                if not ip_changer.validate_ip_in_network(ip, gateway, mask):
                    print("\n⚠ ВНИМАНИЕ: IP не находится в той же подсети, что и шлюз!")
                    print(f"  IP: {ip}")
                    print(f"  Сеть шлюза: {gateway}/{mask}")
                    
                    response = input("Продолжить? (y/n): ").strip().lower()
                    if response != 'y':
                        print("Операция отменена.")
                        return
            
            
            if ip_changer.os_type == 'Windows':
                success = ip_changer.change_ip_windows(interface, ip, mask, gateway)
            else:
                success = ip_changer.change_ip_linux(interface, ip, mask, gateway)
            
            if success:
                print("\n✓ Настройки успешно применены!")
            else:
                print("\n✗ Ошибка применения настроек!")
    
        if mode in ['dhcp', 'static']:
            print("\n" + "-"*30)
            print("ПРОВЕРКА НОВЫХ НАСТРОЕК")
            print("-"*30)
            time.sleep(3)
            
            new_config = ip_changer.get_current_ip(interface)
            if new_config:
                for key, value in new_config.items():
                    print(f"  {key}: {value}")
            else:
                print("  Не удалось получить новые настройки")
            
            print("\n" + "-"*30)
            print("ТЕСТ ПОДКЛЮЧЕНИЯ")
            print("-"*30)
            
            test_target = gateway or '8.8.8.8' or '192.168.1.1'
            print(f"Тестируем ping до {test_target}...")
            
            if ip_changer.os_type == 'Windows':
                ping_cmd = ['ping', '-n', '2', '-w', '1000', test_target]
            else:
                ping_cmd = ['ping', '-c', '2', '-W', '1', test_target]
            
            ping_success, ping_output = ip_changer.run_command(ping_cmd)
            if ping_success:
                print("✓ Сетевое подключение работает")
            else:
                print("✗ Проблемы с сетевым подключением")
                
    except KeyboardInterrupt:
        print("\n\nОперация прервана пользователем")
    except Exception as e:
        print(f"\n✗ Критическая ошибка: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    if sys.version_info < (3, 6):
        print("Требуется Python 3.6 или выше!")
        sys.exit(1)
    
    try:
        main()
    except Exception as e:
        print(f"\nНепредвиденная ошибка: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

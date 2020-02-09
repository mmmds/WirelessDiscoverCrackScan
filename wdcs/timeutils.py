import datetime


class TimeUtils(object):

    @classmethod
    def now(cls):
        return datetime.datetime.now()

    @classmethod
    def now_str(cls):
        return cls.now().strftime("%Y-%m-%d %H:%M")

    @classmethod
    def parse(cls, str):
        return datetime.datetime.strptime(str, "%Y-%m-%d %H:%M")

    @classmethod
    def calc_minutes_diff(cls, dt1, dt2):
        return int((dt1 - dt2).seconds / 60)

    @classmethod
    def normalize_airodump_time(cls, str):
        return ":".join(str.split(":")[:2])
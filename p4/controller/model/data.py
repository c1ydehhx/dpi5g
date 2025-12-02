from typing import Any, List

from bfrt_grpc.client import DataTuple


class Data:
    def __init__(self, key: str, data: int = None, int_arr_val: List[int] = None, bool_arr_val: List[bool] = None, bool_val: bool = None):
        self.key = key
        self.data = data
        self.int_arr_val = int_arr_val
        self.bool_arr_val = bool_arr_val
        self.bool_val = bool_val
    
    def __repr__(self):
        if self.int_arr_val != None:
            return f"Data(key={self.key}, int_arr_val={self.int_arr_val})"
        elif self.bool_arr_val != None:
            return f"Data(key={self.key}, bool_arr_val={self.bool_arr_val})"
        elif self.bool_val != None:
            return f"Data(key={self.key}, bool_val={self.bool_val})"
        elif self.data != None:
            return f"Data(key={self.key}, data={self.data})"
        else:
            return f"Data(None())"
        
    
    def to_bfrt_data(self):
        if self.int_arr_val != None:
            return DataTuple(self.key, int_arr_val=self.int_arr_val)
        elif self.bool_arr_val != None:
            return DataTuple(self.key, bool_arr_val=self.bool_arr_val)
        elif self.bool_val != None:
            return DataTuple(self.key, bool_val=self.bool_val)
        elif self.data != None:
            return DataTuple(self.key, self.data)
        else:
            raise ValueError("Data is None.")
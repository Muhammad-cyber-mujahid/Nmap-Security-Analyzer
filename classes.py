from logging import Manager


class Employee:

    raise_amount = 1.04
    nums_emp = 0

    def __init__(self, first_name, last_name, payment, raised=None):
        self.first_name = first_name
        self.last_name = last_name
        self.payment = int(payment)
        self.email = f"{first_name}.{last_name}@gmail.com"

        # Handle raised properly
        if raised is not None:
            self.raised = int(raised)
        else:
            self.raised = int(self.payment * self.raise_amount)

        Employee.nums_emp += 1

    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def apply_rate(self):
        self.payment = int(self.payment * self.raise_amount)
        self.raised = self.payment  # keep it consistent

    @classmethod
    def set_raise_amount(cls, amount):
        cls.raise_amount = amount

    @classmethod
    def from_string(cls, emp_string):
        first_name, last_name, payment, raised = emp_string.split("-")
        return cls(first_name, last_name, payment, raised)

    @staticmethod
    def is_workday(day):
        if day.weekday() == 5 or day.weekday() == 6:
            return True
        return False

# ================== OUTPUT ==================


class Developer(Employee):
    raise_amount = 10
    def __init__(self, first_name, last_name, payment, prog_lang, raised=None):
        super().__init__(first_name,last_name,payment)
        self.prog_lang = " "

class Administrator(Employee):

    def __init__(self, first_name, last_name, payment, employed = None):
        super().__init__(first_name,last_name, payment)
        if employed is None:
            self.employed = []
        else:
            self.employed = employed

    def add_employee(self, emp):
        if emp not in self.employed:
            self.employed.append(emp)

    def remove_employee(self, emp):
        if emp in self.employed:
            self.employed.remove(emp)

    def print_employee(self):
        for emp in self.employed:
            print('-->', emp.full_name())

    def __repr__(self):
        return "Employee({}, {}, {}, {})".format(self.first_name, self.last_name, self.payment, self.employed)

    def __str__(self):
        return "Employee({}, {}, {}, {})".format(self.first_name, self.last_name, self.payment, self.employed)


dev_1 = Developer('David', 'John', 150 , 'Python')
dev_2 = Developer('David', 'Doe', 750, 'Java')


manager1 = Administrator('David', 'John', 150, employed= [dev_1, dev_2])
manager2 = Administrator('David', 'Doe', 750, [dev_1, dev_2])


print(manager1.__repr__())
print(manager2.__repr__())

print(repr(manager1))
print(repr(manager2))














###Methods are functions associated with a class
##While attributes are basically just variables
## A class is a blueprint for creating an instance
# Instance variable contains data that is unique to each instance


### class variables are variables that are shared amongst all instances of
### a class while instance variables can be unique for each class
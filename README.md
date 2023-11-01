# قالب پروژه‌های C و ‌CPP

در این پروژه، سعی شده تمامی نیازمندی‌های یک پروژه C/CPP لحاظ شود.

در صورتی که موردی نادیده گرفته شده یا در بخشی نقصی وجود دارد، آن را در یک شاخه جدا تصحیح کرده و Merge Request دهید تا در شاخه اصلی نیز اعمال شود.

## کامپایل پروژه

برای بیلد کردن و کامپایل پروژه از روند زیر استفاده نمایید.

```
mkdir build
cd build
cmake ..
make -j`nproc`
```

لطفا پرچم‌هایی که برای کامپایل پروژه اضافه شده است را دستکاری نکنید؛ این پرچم‌ها در بهتر شدن کد شما بسیار مؤثر است.

## افرودن زیرماژول

برای افزودن زیرماژول می‌توانید از دستور زیر استفاده کنید.

```
git submodule add [REPOSITORY LINK] [/path/to/destination]
```
به عنوان مثال
```
git submodule add git@git.yaftar.ir:ts/submodule-template.git third-party/submodule
```

یا از طریق زیر 
```
cd third-party
git submodule add [REPOSITORY LINK]
```
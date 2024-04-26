.PHONY: cv clean cv_en cv_zh dependencies

CC = xelatex
CVS_DIR = cvs
CLS = awesome-cv.cls

CV_EN_DIR = $(CVS_DIR)/cv_en
CV_EN_SRCS = $(shell find $(CV_EN_DIR)/cv -name '*.tex')

CV_ZH_DIR = $(CVS_DIR)/cv_zh
CV_ZH_SRCS = $(shell find $(CV_ZH_DIR)/cv -name '*.tex')

CC_PACKAGE = $(shell apt list --installed 2>/dev/null | egrep "texlive")

cv: clean dependencies cv_en cv_zh

dependencies:
	if [ "$(CC_PACKAGE)" = "" ]; then \
		sudo apt-get install -y texlive-full texlive-xetex texlive-lang-chinese; \
	fi

cv_en: $(CV_EN_DIR)/cv.tex $(CV_EN_SRCS) $(CLS)
	$(CC) -output-directory=$(CV_EN_DIR) $<
	mv $(CV_EN_DIR)/cv.pdf cv_en.pdf

cv_zh: $(CV_ZH_DIR)/cv.tex $(CV_ZH_SRCS) $(CLS)
	$(CC) -output-directory=$(CV_ZH_DIR) $<
	mv $(CV_ZH_DIR)/cv.pdf cv_zh.pdf

clean:
	rm -rf $(shell find . -name '*.pdf')
	rm -rf $(shell find . -name '*.aux')
	rm -rf $(shell find . -name '*.log')

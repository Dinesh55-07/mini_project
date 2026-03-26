(function () {
  function toBool(value, fallback) {
    if (value === undefined || value === null || value === "") {
      return fallback;
    }
    return String(value).toLowerCase() === "true";
  }

  function uniqueChars(text) {
    var seen = new Set();
    var out = [];
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (ch !== " " && !seen.has(ch)) {
        seen.add(ch);
        out.push(ch);
      }
    }
    return out;
  }

  function computeOrder(length, direction) {
    var order = [];
    var i;
    if (direction === "end") {
      for (i = length - 1; i >= 0; i--) {
        order.push(i);
      }
      return order;
    }
    if (direction === "center") {
      var middle = Math.floor(length / 2);
      var offset = 0;
      while (order.length < length) {
        if (offset % 2 === 0) {
          var idxA = middle + offset / 2;
          if (idxA >= 0 && idxA < length) {
            order.push(idxA);
          }
        } else {
          var idxB = middle - Math.ceil(offset / 2);
          if (idxB >= 0 && idxB < length) {
            order.push(idxB);
          }
        }
        offset++;
      }
      return order;
    }

    for (i = 0; i < length; i++) {
      order.push(i);
    }
    return order;
  }

  function DecryptedText(el) {
    this.el = el;
    this.text = el.dataset.text || el.textContent || "";
    this.speed = parseInt(el.dataset.speed || "50", 10);
    this.maxIterations = parseInt(el.dataset.maxIterations || "10", 10);
    this.sequential = toBool(el.dataset.sequential, false);
    this.revealDirection = el.dataset.revealDirection || "start";
    this.useOriginalCharsOnly = toBool(el.dataset.useOriginalCharsOnly, false);
    this.characters = el.dataset.characters || "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+";
    this.animateOn = el.dataset.animateOn || "hover";
    this.clickMode = el.dataset.clickMode || "once";
    this.revealedClass = el.dataset.revealedClass || "";
    this.encryptedClass = el.dataset.encryptedClass || "dt-encrypted";

    this.availableChars = this.useOriginalCharsOnly ? uniqueChars(this.text) : this.characters.split("");
    if (!this.availableChars.length) {
      this.availableChars = this.characters.split("");
    }

    this.order = computeOrder(this.text.length, this.revealDirection);
    this.revealed = new Set();
    this.interval = null;
    this.isAnimating = false;
    this.isDecrypted = this.animateOn !== "click";
    this.hasAnimatedOnView = false;

    this.el.classList.add("decrypted-text");
    this.render(this.text, true);

    this.bind();
    if (this.animateOn === "click") {
      this.render(this.scramble(this.revealed), false);
    }
    if (this.animateOn === "view") {
      this.render(this.scramble(this.revealed), false);
      this.observeView();
    }
  }

  DecryptedText.prototype.randomChar = function () {
    return this.availableChars[Math.floor(Math.random() * this.availableChars.length)] || "*";
  };

  DecryptedText.prototype.scramble = function (revealedSet) {
    var out = "";
    for (var i = 0; i < this.text.length; i++) {
      var ch = this.text[i];
      if (ch === " ") {
        out += " ";
      } else if (revealedSet.has(i)) {
        out += ch;
      } else {
        out += this.randomChar();
      }
    }
    return out;
  };

  DecryptedText.prototype.render = function (display, done) {
    this.el.textContent = "";
    for (var i = 0; i < display.length; i++) {
      var span = document.createElement("span");
      span.textContent = display[i];
      var revealed = done || this.revealed.has(i);
      if (revealed) {
        if (this.revealedClass) {
          span.className = this.revealedClass;
        }
      } else {
        span.className = this.encryptedClass;
      }
      this.el.appendChild(span);
    }
  };

  DecryptedText.prototype.stop = function () {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.isAnimating = false;
  };

  DecryptedText.prototype.animateForward = function () {
    var self = this;
    self.stop();
    self.isAnimating = true;
    self.revealed = new Set();

    if (self.sequential) {
      var pointer = 0;
      self.interval = setInterval(function () {
        if (pointer < self.order.length) {
          self.revealed.add(self.order[pointer]);
          self.render(self.scramble(self.revealed), false);
          pointer += 1;
          return;
        }
        self.stop();
        self.isDecrypted = true;
        self.render(self.text, true);
      }, self.speed);
      return;
    }

    var iteration = 0;
    self.interval = setInterval(function () {
      self.render(self.scramble(self.revealed), false);
      iteration += 1;
      if (iteration >= self.maxIterations) {
        self.stop();
        self.isDecrypted = true;
        self.render(self.text, true);
      }
    }, self.speed);
  };

  DecryptedText.prototype.animateReverse = function () {
    var self = this;
    self.stop();
    self.isAnimating = true;

    var all = new Set();
    for (var i = 0; i < self.text.length; i++) {
      all.add(i);
    }
    self.revealed = all;

    if (self.sequential) {
      var reverseOrder = self.order.slice().reverse();
      var pointer = 0;
      self.interval = setInterval(function () {
        if (pointer < reverseOrder.length) {
          self.revealed.delete(reverseOrder[pointer]);
          self.render(self.scramble(self.revealed), false);
          pointer += 1;
          return;
        }
        self.stop();
        self.isDecrypted = false;
      }, self.speed);
      return;
    }

    var iteration = 0;
    self.interval = setInterval(function () {
      var arr = Array.from(self.revealed);
      var removeCount = Math.max(1, Math.ceil(self.text.length / Math.max(1, self.maxIterations)));
      for (var r = 0; r < removeCount && arr.length > 0; r++) {
        var idx = Math.floor(Math.random() * arr.length);
        self.revealed.delete(arr[idx]);
        arr.splice(idx, 1);
      }
      self.render(self.scramble(self.revealed), false);
      iteration += 1;
      if (!self.revealed.size || iteration >= self.maxIterations) {
        self.stop();
        self.isDecrypted = false;
      }
    }, self.speed);
  };

  DecryptedText.prototype.observeView = function () {
    var self = this;
    if (!("IntersectionObserver" in window)) {
      self.animateForward();
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !self.hasAnimatedOnView) {
          self.hasAnimatedOnView = true;
          self.animateForward();
          observer.unobserve(self.el);
        }
      });
    }, { threshold: 0.1 });

    observer.observe(self.el);
  };

  DecryptedText.prototype.bind = function () {
    var self = this;

    if (self.animateOn === "hover") {
      self.el.addEventListener("mouseenter", function () {
        if (!self.isAnimating) {
          self.animateForward();
        }
      });

      self.el.addEventListener("mouseleave", function () {
        self.stop();
        self.revealed = new Set();
        self.isDecrypted = true;
        self.render(self.text, true);
      });
      return;
    }

    if (self.animateOn === "click") {
      self.el.style.cursor = "pointer";
      self.el.addEventListener("click", function () {
        if (self.clickMode === "once") {
          if (!self.isDecrypted) {
            self.animateForward();
          }
          return;
        }

        if (self.isDecrypted) {
          self.animateReverse();
        } else {
          self.animateForward();
        }
      });
    }
  };

  document.addEventListener("DOMContentLoaded", function () {
    var nodes = document.querySelectorAll("[data-decrypted-text]");
    nodes.forEach(function (node) {
      var text = node.dataset.text || node.textContent || "";
      node.dataset.text = text;
      new DecryptedText(node);
    });
  });
})();

module.exports = () => {
  return {
    getDateTime: () => {
      const currentdate = new Date();
      const datetime =
        '[' +
        currentdate.getDate() +
        '/' +
        (currentdate.getMonth() + 1) +
        '/' +
        currentdate.getFullYear() +
        ':' +
        currentdate.getHours() +
        ':' +
        currentdate.getMinutes() +
        ':' +
        currentdate.getSeconds() +
        ' ' +
        (currentdate.getTimezoneOffset() / 60).toString() +
        ']';
      return datetime;
    },
  };
};

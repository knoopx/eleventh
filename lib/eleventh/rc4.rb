module Eleventh
  class RC4
    def initialize(key)
      @key = []
      @q1, @q2 = 0, 0
      key.each_byte { |elem| @key << elem } while @key.size < 256
      @key.slice!(256..@key.size-1) if @key.size >= 256
      @s = (0..255).to_a

      j = 0
      0.upto(255) do |i|
        j = (j + @s[i] + @key[i]) % 256
        @s[i], @s[j] = @s[j], @s[i]
      end
    end

    def process(input)
      output = input.clone
      0.upto(output.length - 1) { |i| output[i] = (output[i].ord ^ round).chr }
      output
    end

    protected

    def round
      @q1 = (@q1 + 1) % 256
      @q2 = (@q2 + @s[@q1]) % 256
      @s[@q1], @s[@q2] = @s[@q2], @s[@q1]
      @s[(@s[@q1] + @s[@q2]) % 256]
    end
  end
end
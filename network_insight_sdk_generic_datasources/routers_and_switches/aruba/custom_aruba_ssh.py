
import time
from netmiko.aruba.aruba_ssh import ArubaSSH


class CustomArubaSSH(ArubaSSH):

    def session_preparation(self):
        """Aruba OS requires enable mode to disable paging."""
        # Aruba switches output ansi codes
        self.ansi_escape_codes = True

        delay_factor = self.select_delay_factor(delay_factor=0)
        time.sleep(1 * delay_factor)
        self._test_channel_read()
        self.set_base_prompt()
        self.disable_paging(command="no paging")
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    # def read_channel(self):
    #     output = super().read_channel()
    #     if "MORE" in output:
    #         self.write_channel(self.RETURN)
    #         # remove MORE from output
    #     return output
